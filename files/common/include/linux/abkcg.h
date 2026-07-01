/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ABKCG_H
#define _LINUX_ABKCG_H

#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/threads.h>

#ifdef CONFIG_ABK_CGROUP

#define ABKCG_PIDS_MAX ((s64)PID_MAX_LIMIT + 1)
#define ABKCG_CTL_PIDS    0x1
#define ABKCG_CTL_DEVICES 0x2

struct abkcg_device_rule {
	struct list_head node;
	u32 major;
	u32 minor;
	short type;
	short access;
	bool allow;
};

struct abkcg_cgroup {
	struct cgroup *cgrp;
	atomic64_t pids_current;
	atomic64_t pids_limit;
	s64 pids_peak;
	struct mutex devices_lock;
	struct list_head devices_rules;
};

struct abkcg_mount_record {
	struct list_head node;
	u64 mount_id;
	u64 ns_inum;
	char source[PATH_MAX];
};

struct abkcg_file_ctx {
	struct cgroup *cgrp;
	char name[NAME_MAX];
};

bool abkcg_is_enabled(void);
void abkcg_set_enabled(bool enabled);
int abkcg_sysfs_init(void);
void abkcg_sysfs_exit(void);
u64 abkcg_mount_registered(u64 ns_inum, const char *source);
void abkcg_mount_unregistered(u64 mount_id, u64 ns_inum);

int abkcg_fork(struct task_struct *task);
void abkcg_fork_failed(struct task_struct *task);
void abkcg_exit(struct task_struct *task);
void abkcg_migrate(struct task_struct *task, struct cgroup *src,
		   struct cgroup *dst, bool threadgroup);
int abkcg_dev_check_permission(short type, u32 major, u32 minor, short access);
bool abkcg_is_shadow_file(const char *name);
bool abkcg_is_intercepted_file(const char *name);
struct abkcg_file_ctx *abkcg_ctx_from_dentry(struct dentry *dentry, const char *name);
void abkcg_ctx_put(struct abkcg_file_ctx *ctx);
unsigned int abkcg_available_controllers(struct cgroup *cgrp);
unsigned int abkcg_subtree_control(struct cgroup *cgrp);
int abkcg_write_subtree_control(struct cgroup *cgrp, const char *buf, size_t size,
				char *pass_buf, size_t pass_buf_size);
void abkcg_reset_cgroup(struct cgroup *cgrp);
ssize_t abkcg_read_file(struct cgroup *cgrp, const char *name,
			char *buf, size_t size, loff_t *ppos);
ssize_t abkcg_write_file(struct cgroup *cgrp, const char *name,
			 const char *buf, size_t size);
ssize_t abkcg_sepolicy_apply_cmd(const char *buf, size_t size);

#else

struct abkcg_cgroup;

static inline bool abkcg_is_enabled(void)
{
	return false;
}

static inline void abkcg_set_enabled(bool enabled)
{
}

static inline int abkcg_sysfs_init(void)
{
	return 0;
}

static inline void abkcg_sysfs_exit(void)
{
}

static inline u64 abkcg_mount_registered(u64 ns_inum, const char *source)
{
	return 0;
}

static inline void abkcg_mount_unregistered(u64 mount_id, u64 ns_inum)
{
}

static inline int abkcg_fork(struct task_struct *task)
{
	return 0;
}

static inline void abkcg_fork_failed(struct task_struct *task)
{
}

static inline void abkcg_exit(struct task_struct *task)
{
}

static inline void abkcg_migrate(struct task_struct *task, struct cgroup *src,
				 struct cgroup *dst, bool threadgroup)
{
}

static inline int abkcg_dev_check_permission(short type, u32 major, u32 minor,
					     short access)
{
	return 0;
}

static inline bool abkcg_is_shadow_file(const char *name)
{
	return false;
}

static inline bool abkcg_is_intercepted_file(const char *name)
{
	return false;
}

static inline struct abkcg_file_ctx *abkcg_ctx_from_dentry(struct dentry *dentry,
							   const char *name)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void abkcg_ctx_put(struct abkcg_file_ctx *ctx)
{
}

static inline unsigned int abkcg_available_controllers(struct cgroup *cgrp)
{
	return 0;
}

static inline unsigned int abkcg_subtree_control(struct cgroup *cgrp)
{
	return 0;
}

static inline int abkcg_write_subtree_control(struct cgroup *cgrp,
					      const char *buf, size_t size,
					      char *pass_buf, size_t pass_buf_size)
{
	return -EOPNOTSUPP;
}

static inline void abkcg_reset_cgroup(struct cgroup *cgrp)
{
}

static inline ssize_t abkcg_read_file(struct cgroup *cgrp, const char *name,
				      char *buf, size_t size, loff_t *ppos)
{
	return -EOPNOTSUPP;
}

static inline ssize_t abkcg_write_file(struct cgroup *cgrp, const char *name,
				       const char *buf, size_t size)
{
	return -EOPNOTSUPP;
}

static inline ssize_t abkcg_sepolicy_apply_cmd(const char *buf, size_t size)
{
	return -EOPNOTSUPP;
}

#endif

#endif
