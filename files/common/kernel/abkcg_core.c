// SPDX-License-Identifier: GPL-2.0-only
#include <linux/abkcg.h>

#ifdef CONFIG_ABK_CGROUP

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/device_cgroup.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kstrtox.h>
#include <linux/list.h>
#include <linux/mnt_namespace.h>
#include <linux/mutex.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#define ABKCG_HASH_BITS 8

struct abkcg_group_state {
	struct hlist_node node;
	struct cgroup *cgrp;
	atomic64_t pids_current;
	atomic64_t pids_limit;
	s64 pids_peak;
	unsigned int subtree_control;
	struct mutex devices_lock;
	struct list_head devices_rules;
};

static bool abkcg_enabled;
static atomic64_t abkcg_mount_id = ATOMIC_INIT(1);
static DEFINE_MUTEX(abkcg_mounts_lock);
static LIST_HEAD(abkcg_mounts);
static struct kobject *abkcg_kobj;

static DEFINE_MUTEX(abkcg_groups_lock);
static DEFINE_HASHTABLE(abkcg_groups, ABKCG_HASH_BITS);

static struct abkcg_group_state *abkcg_state_lookup(struct cgroup *cgrp)
{
	struct abkcg_group_state *state;

	hash_for_each_possible(abkcg_groups, state, node, (unsigned long)cgrp) {
		if (state->cgrp == cgrp)
			return state;
	}

	return NULL;
}

struct abkcg_file_ctx *abkcg_ctx_from_dentry(struct dentry *dentry, const char *name)
{
	struct cgroup_subsys_state *css;
	struct abkcg_file_ctx *ctx;

	css = css_tryget_online_from_dir(dentry, NULL);
	if (IS_ERR(css))
		return ERR_CAST(css);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		css_put(css);
		return ERR_PTR(-ENOMEM);
	}

	ctx->cgrp = css->cgroup;
	cgroup_get(ctx->cgrp);
	css_put(css);
	strscpy(ctx->name, name, sizeof(ctx->name));
	return ctx;
}

void abkcg_ctx_put(struct abkcg_file_ctx *ctx)
{
	if (IS_ERR_OR_NULL(ctx))
		return;
	if (ctx->cgrp)
		cgroup_put(ctx->cgrp);
	kfree(ctx);
}

static struct abkcg_group_state *abkcg_state_get(struct cgroup *cgrp, bool create)
{
	struct abkcg_group_state *state;

	mutex_lock(&abkcg_groups_lock);
	state = abkcg_state_lookup(cgrp);
	if (!state && create) {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (state) {
			state->cgrp = cgrp;
			atomic64_set(&state->pids_limit, ABKCG_PIDS_MAX);
			mutex_init(&state->devices_lock);
			INIT_LIST_HEAD(&state->devices_rules);
			cgroup_get(cgrp);
			hash_add(abkcg_groups, &state->node, (unsigned long)cgrp);
		}
	}
	mutex_unlock(&abkcg_groups_lock);
	return state;
}

static void abkcg_state_clear_locked(struct abkcg_group_state *state)
{
	struct abkcg_device_rule *rule, *tmp;

	atomic64_set(&state->pids_limit, ABKCG_PIDS_MAX);
	WRITE_ONCE(state->pids_peak, atomic64_read(&state->pids_current));
	state->subtree_control = 0;
	list_for_each_entry_safe(rule, tmp, &state->devices_rules, node) {
		list_del(&rule->node);
		kfree(rule);
	}
}

static bool abkcg_has_active_mounts(void)
{
	return !list_empty(&abkcg_mounts);
}

static bool abkcg_namespace_registered(struct task_struct *task)
{
	struct abkcg_mount_record *record;
	u64 ns_inum;
	bool found = false;

	if (!task->nsproxy || !task->nsproxy->mnt_ns)
		return false;

	ns_inum = from_mnt_ns(task->nsproxy->mnt_ns)->inum;
	mutex_lock(&abkcg_mounts_lock);
	list_for_each_entry(record, &abkcg_mounts, node) {
		if (record->ns_inum == ns_inum) {
			found = true;
			break;
		}
	}
	mutex_unlock(&abkcg_mounts_lock);
	return found;
}

static bool abkcg_task_is_tracked(struct task_struct *task)
{
	return abkcg_is_enabled() && abkcg_has_active_mounts() &&
	       abkcg_namespace_registered(task) && task_dfl_cgroup(task);
}

static void abkcg_update_peak(struct abkcg_group_state *state, s64 value)
{
	s64 old = READ_ONCE(state->pids_peak);
	s64 prev;

	while (value > old) {
		prev = cmpxchg64(&state->pids_peak, old, value);
		if (prev == old)
			break;
		old = prev;
	}
}

static int abkcg_access_mask(const char *str)
{
	int access = 0;

	while (*str) {
		switch (*str++) {
		case 'r':
			access |= DEVCG_ACC_READ;
			break;
		case 'w':
			access |= DEVCG_ACC_WRITE;
			break;
		case 'm':
			access |= DEVCG_ACC_MKNOD;
			break;
		default:
			return -EINVAL;
		}
	}

	return access;
}

static bool abkcg_rule_matches(const struct abkcg_device_rule *rule, short type,
			       u32 major, u32 minor, short access)
{
	if (rule->type != DEVCG_DEV_ALL && rule->type != type)
		return false;
	if (rule->major != U32_MAX && rule->major != major)
		return false;
	if (rule->minor != U32_MAX && rule->minor != minor)
		return false;
	if ((rule->access & access) != access)
		return false;
	return true;
}

static char *abkcg_num_or_wild(u32 value, char *buf, size_t len)
{
	if (value == U32_MAX) {
		strscpy(buf, "*", len);
		return buf;
	}

	snprintf(buf, len, "%u", value);
	return buf;
}

static const char *abkcg_access_to_str(short access)
{
	switch (access) {
	case DEVCG_ACC_READ | DEVCG_ACC_WRITE | DEVCG_ACC_MKNOD:
		return "rwm";
	case DEVCG_ACC_READ | DEVCG_ACC_WRITE:
		return "rw";
	case DEVCG_ACC_READ | DEVCG_ACC_MKNOD:
		return "rm";
	case DEVCG_ACC_WRITE | DEVCG_ACC_MKNOD:
		return "wm";
	case DEVCG_ACC_READ:
		return "r";
	case DEVCG_ACC_WRITE:
		return "w";
	case DEVCG_ACC_MKNOD:
		return "m";
	default:
		return "";
	}
}

static ssize_t abkcg_emit_simple(const char *src, char *buf, size_t size, loff_t *ppos)
{
	size_t len = strlen(src);
	size_t off;
	size_t n;

	if (*ppos < 0)
		return -EINVAL;

	off = min_t(size_t, *ppos, len);
	n = min(size, len - off);
	memcpy(buf, src + off, n);
	*ppos += n;
	return n;
}

static ssize_t abkcg_emit_num(s64 value, char *buf, size_t size, loff_t *ppos)
{
	char tmp[64];

	snprintf(tmp, sizeof(tmp), "%lld\n", value);
	return abkcg_emit_simple(tmp, buf, size, ppos);
}

bool abkcg_is_enabled(void)
{
	return READ_ONCE(abkcg_enabled);
}

void abkcg_set_enabled(bool enabled)
{
	WRITE_ONCE(abkcg_enabled, enabled);
}

int abkcg_fork(struct task_struct *task)
{
	struct abkcg_group_state *state;
	s64 current_count;
	s64 limit;

	if (!abkcg_task_is_tracked(current))
		return 0;

	state = abkcg_state_get(task_dfl_cgroup(current), true);
	if (!state)
		return -ENOMEM;

	current_count = atomic64_add_return(1, &state->pids_current);
	abkcg_update_peak(state, current_count);
	limit = atomic64_read(&state->pids_limit);
	if (current_count > limit) {
		atomic64_add(-1, &state->pids_current);
		return -EAGAIN;
	}

	return 0;
}

void abkcg_fork_failed(struct task_struct *task)
{
	struct abkcg_group_state *state;

	if (!abkcg_task_is_tracked(current))
		return;

	state = abkcg_state_get(task_dfl_cgroup(current), false);
	if (!state)
		return;

	WARN_ON_ONCE(atomic64_add_negative(-1, &state->pids_current));
}

void abkcg_exit(struct task_struct *task)
{
	struct abkcg_group_state *state;

	if (!abkcg_task_is_tracked(task))
		return;

	state = abkcg_state_get(task_dfl_cgroup(task), false);
	if (!state)
		return;

	WARN_ON_ONCE(atomic64_add_negative(-1, &state->pids_current));
}

void abkcg_migrate(struct task_struct *task, struct cgroup *src,
		   struct cgroup *dst, bool threadgroup)
{
	struct abkcg_group_state *src_state;
	struct abkcg_group_state *dst_state;

	if (!abkcg_task_is_tracked(task) || !src || !dst || src == dst)
		return;

	src_state = abkcg_state_get(src, false);
	dst_state = abkcg_state_get(dst, true);
	if (!dst_state)
		return;

	if (src_state)
		WARN_ON_ONCE(atomic64_add_negative(-1, &src_state->pids_current));
	abkcg_update_peak(dst_state, atomic64_add_return(1, &dst_state->pids_current));
}

int abkcg_dev_check_permission(short type, u32 major, u32 minor, short access)
{
	struct abkcg_group_state *state;
	struct abkcg_device_rule *rule;
	int allowed = 1;

	if (!abkcg_task_is_tracked(current))
		return 0;

	state = abkcg_state_get(task_dfl_cgroup(current), false);
	if (!state)
		return 0;

	mutex_lock(&state->devices_lock);
	list_for_each_entry(rule, &state->devices_rules, node) {
		if (!abkcg_rule_matches(rule, type, major, minor, access))
			continue;
		allowed = rule->allow ? 1 : 0;
	}
	mutex_unlock(&state->devices_lock);
	return allowed ? 0 : -EPERM;
}

bool abkcg_is_shadow_file(const char *name)
{
	return !strcmp(name, "pids.max") ||
	       !strcmp(name, "pids.current") ||
	       !strcmp(name, "pids.peak") ||
	       !strcmp(name, "devices.allow") ||
	       !strcmp(name, "devices.deny") ||
	       !strcmp(name, "devices.list");
}

bool abkcg_is_intercepted_file(const char *name)
{
	return abkcg_is_shadow_file(name) ||
	       !strcmp(name, "cgroup.controllers") ||
	       !strcmp(name, "cgroup.subtree_control");
}

unsigned int abkcg_available_controllers(struct cgroup *cgrp)
{
	struct cgroup *parent;
	struct abkcg_group_state *state;

	if (!cgrp)
		return 0;

	parent = cgroup_parent(cgrp);
	if (!parent)
		return ABKCG_CTL_PIDS | ABKCG_CTL_DEVICES;

	state = abkcg_state_get(parent, false);
	return state ? state->subtree_control : 0;
}

unsigned int abkcg_subtree_control(struct cgroup *cgrp)
{
	struct abkcg_group_state *state = abkcg_state_get(cgrp, false);

	return state ? state->subtree_control : 0;
}

int abkcg_write_subtree_control(struct cgroup *cgrp, const char *buf, size_t size,
				char *pass_buf, size_t pass_buf_size)
{
	struct abkcg_group_state *state;
	char *tmp, *cursor, *tok;
	int ret = 0;
	size_t used = 0;

	state = abkcg_state_get(cgrp, true);
	if (!state)
		return -ENOMEM;

	tmp = kmemdup_nul(buf, size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	cursor = strim(tmp);
	while ((tok = strsep(&cursor, " "))) {
		if (!*tok)
			continue;
		if (!strcmp(tok, "+pids"))
			state->subtree_control |= ABKCG_CTL_PIDS;
		else if (!strcmp(tok, "-pids"))
			state->subtree_control &= ~ABKCG_CTL_PIDS;
		else if (!strcmp(tok, "+devices"))
			state->subtree_control |= ABKCG_CTL_DEVICES;
		else if (!strcmp(tok, "-devices"))
			state->subtree_control &= ~ABKCG_CTL_DEVICES;
		else {
			used += scnprintf(pass_buf + used, pass_buf_size - used,
					  "%s%s", used ? " " : "", tok);
			if (used >= pass_buf_size) {
				ret = -ENOSPC;
				break;
			}
		}
	}

	kfree(tmp);
	return ret ? ret : (int)used;
}

void abkcg_reset_cgroup(struct cgroup *cgrp)
{
	struct abkcg_group_state *state = abkcg_state_get(cgrp, false);

	if (!state)
		return;

	mutex_lock(&state->devices_lock);
	abkcg_state_clear_locked(state);
	mutex_unlock(&state->devices_lock);
}

ssize_t abkcg_read_file(struct cgroup *cgrp, const char *name,
			char *buf, size_t size, loff_t *ppos)
{
	struct abkcg_group_state *state = abkcg_state_get(cgrp, true);

	if (!state)
		return -ENOMEM;

	if (!strcmp(name, "pids.max")) {
		s64 limit = atomic64_read(&state->pids_limit);

		if (limit >= ABKCG_PIDS_MAX)
			return abkcg_emit_simple("max\n", buf, size, ppos);
		return abkcg_emit_num(limit, buf, size, ppos);
	}

	if (!strcmp(name, "pids.current"))
		return abkcg_emit_num(atomic64_read(&state->pids_current), buf, size, ppos);

	if (!strcmp(name, "pids.peak"))
		return abkcg_emit_num(READ_ONCE(state->pids_peak), buf, size, ppos);

	if (!strcmp(name, "devices.allow") || !strcmp(name, "devices.deny"))
		return 0;

	if (!strcmp(name, "devices.list")) {
		struct abkcg_device_rule *rule;
		char maj[16];
		char min[16];
		size_t used = 0;
		char *tmp;
		ssize_t ret;

		tmp = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;

		mutex_lock(&state->devices_lock);
		list_for_each_entry(rule, &state->devices_rules, node) {
			if (!rule->allow)
				continue;
			used += scnprintf(tmp + used, PAGE_SIZE - used, "%c %s:%s %s\n",
					  rule->type == DEVCG_DEV_ALL ? 'a' :
					  rule->type == DEVCG_DEV_BLOCK ? 'b' : 'c',
					  abkcg_num_or_wild(rule->major, maj, sizeof(maj)),
					  abkcg_num_or_wild(rule->minor, min, sizeof(min)),
					  abkcg_access_to_str(rule->access));
			if (used >= PAGE_SIZE)
				break;
		}
		mutex_unlock(&state->devices_lock);

		ret = abkcg_emit_simple(tmp, buf, size, ppos);
		kfree(tmp);
		return ret;
	}

	return -ENOENT;
}

ssize_t abkcg_write_file(struct cgroup *cgrp, const char *name,
			 const char *buf, size_t size)
{
	struct abkcg_group_state *state = abkcg_state_get(cgrp, true);
	char *tmp;
	ssize_t ret = size;

	if (!state)
		return -ENOMEM;

	tmp = kmemdup_nul(buf, size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	if (!strcmp(name, "pids.max")) {
		s64 limit;

		strim(tmp);
		if (!strcmp(tmp, "max")) {
			atomic64_set(&state->pids_limit, ABKCG_PIDS_MAX);
			goto out;
		}

		ret = kstrtos64(tmp, 0, &limit);
		if (ret)
			goto out;

		if (limit < 0 || limit >= ABKCG_PIDS_MAX) {
			ret = -EINVAL;
			goto out;
		}

		atomic64_set(&state->pids_limit, limit);
		goto out;
	}

	if (!strcmp(name, "devices.allow") || !strcmp(name, "devices.deny")) {
		struct abkcg_device_rule *rule;
		char type;
		char maj[16];
		char min[16];
		char acc[8];
		int parsed;

		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule) {
			ret = -ENOMEM;
			goto out;
		}

		strim(tmp);
		parsed = sscanf(tmp, "%c %15[^:]:%15s %7s", &type, maj, min, acc);
		if (parsed != 4) {
			kfree(rule);
			ret = -EINVAL;
			goto out;
		}

		switch (type) {
		case 'a':
			rule->type = DEVCG_DEV_ALL;
			break;
		case 'b':
			rule->type = DEVCG_DEV_BLOCK;
			break;
		case 'c':
			rule->type = DEVCG_DEV_CHAR;
			break;
		default:
			kfree(rule);
			ret = -EINVAL;
			goto out;
		}

		if (!strcmp(maj, "*"))
			rule->major = U32_MAX;
		else if (kstrtou32(maj, 0, &rule->major)) {
			kfree(rule);
			ret = -EINVAL;
			goto out;
		}

		if (!strcmp(min, "*"))
			rule->minor = U32_MAX;
		else if (kstrtou32(min, 0, &rule->minor)) {
			kfree(rule);
			ret = -EINVAL;
			goto out;
		}

		ret = abkcg_access_mask(acc);
		if (ret < 0) {
			kfree(rule);
			goto out;
		}

		rule->access = ret;
		rule->allow = !strcmp(name, "devices.allow");
		mutex_lock(&state->devices_lock);
		list_add_tail(&rule->node, &state->devices_rules);
		mutex_unlock(&state->devices_lock);
		ret = size;
		goto out;
	}

	ret = -EINVAL;

out:
	kfree(tmp);
	return ret;
}

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%u\n", abkcg_is_enabled());
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	bool enabled;
	int ret;

	ret = kstrtobool(buf, &enabled);
	if (ret)
		return ret;

	abkcg_set_enabled(enabled);
	return count;
}

static ssize_t mounts_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	struct abkcg_mount_record *record;
	int used = 0;

	mutex_lock(&abkcg_mounts_lock);
	list_for_each_entry(record, &abkcg_mounts, node) {
		used += sysfs_emit_at(buf, used,
				      "mount_id=%llu ns=%llu source=%s\n",
				      record->mount_id, record->ns_inum,
				      record->source);
		if (used >= PAGE_SIZE)
			break;
	}
	mutex_unlock(&abkcg_mounts_lock);
	return used;
}

static ssize_t groups_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	struct abkcg_group_state *state;
	int bkt;
	int used = 0;
	char path[PATH_MAX];

	mutex_lock(&abkcg_groups_lock);
	hash_for_each(abkcg_groups, bkt, state, node) {
		if (!cgroup_path(state->cgrp, path, sizeof(path))) {
			used += sysfs_emit_at(buf, used,
					      "path=%s current=%lld peak=%lld max=%lld subtree=%u\n",
					      path,
					      atomic64_read(&state->pids_current),
					      READ_ONCE(state->pids_peak),
					      atomic64_read(&state->pids_limit),
					      state->subtree_control);
		}
		if (used >= PAGE_SIZE)
			break;
	}
	mutex_unlock(&abkcg_groups_lock);
	return used;
}

static ssize_t reset_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct cgroup *cgrp;
	char *tmp;

	tmp = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	strim(tmp);
	cgrp = cgroup_get_from_path(tmp);
	kfree(tmp);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	abkcg_reset_cgroup(cgrp);
	cgroup_put(cgrp);
	return count;
}

static struct kobj_attribute enabled_attr = __ATTR_RW(enabled);
static struct kobj_attribute mounts_attr = __ATTR_RO(mounts);
static struct kobj_attribute groups_attr = __ATTR_RO(groups);
static struct kobj_attribute reset_attr = __ATTR_WO(reset);

static struct attribute *abkcg_attrs[] = {
	&enabled_attr.attr,
	&mounts_attr.attr,
	&groups_attr.attr,
	&reset_attr.attr,
	NULL,
};

static const struct attribute_group abkcg_attr_group = {
	.attrs = abkcg_attrs,
};

int abkcg_sysfs_init(void)
{
	int ret;

	abkcg_kobj = kobject_create_and_add("abkcg", kernel_kobj);
	if (!abkcg_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(abkcg_kobj, &abkcg_attr_group);
	if (ret) {
		kobject_put(abkcg_kobj);
		abkcg_kobj = NULL;
	}

	return ret;
}

void abkcg_sysfs_exit(void)
{
	if (!abkcg_kobj)
		return;

	sysfs_remove_group(abkcg_kobj, &abkcg_attr_group);
	kobject_put(abkcg_kobj);
	abkcg_kobj = NULL;
}

u64 abkcg_mount_registered(u64 ns_inum, const char *source)
{
	struct abkcg_mount_record *record;

	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return 0;

	record->mount_id = atomic64_inc_return(&abkcg_mount_id);
	record->ns_inum = ns_inum;
	strscpy(record->source, source ?: "", sizeof(record->source));

	mutex_lock(&abkcg_mounts_lock);
	list_add_tail(&record->node, &abkcg_mounts);
	mutex_unlock(&abkcg_mounts_lock);
	return record->mount_id;
}

void abkcg_mount_unregistered(u64 mount_id, u64 ns_inum)
{
	struct abkcg_mount_record *record, *tmp;

	mutex_lock(&abkcg_mounts_lock);
	list_for_each_entry_safe(record, tmp, &abkcg_mounts, node) {
		if (record->mount_id != mount_id || record->ns_inum != ns_inum)
			continue;
		list_del(&record->node);
		kfree(record);
		break;
	}
	mutex_unlock(&abkcg_mounts_lock);
}

static int __init abkcg_init(void)
{
	hash_init(abkcg_groups);
	return abkcg_sysfs_init();
}
subsys_initcall(abkcg_init);

#endif
