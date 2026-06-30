// SPDX-License-Identifier: GPL-2.0-only
#include <linux/abkcg.h>

#ifdef CONFIG_ABK_CGROUP

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/init.h>
#include <linux/kernfs.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/pseudo_fs.h>
#include <linux/slab.h>
#include <linux/uio.h>

#include "internal.h"
#include "mount.h"

#define ABKCG2FS_MAGIC 0x61626b32
#define ABKCG2FS_SHADOW_POS_BASE (1ULL << 62)

enum {
	Opt_source,
};

struct abkcg2fs_mount_opts {
	struct path lower_root;
	char source[PATH_MAX];
};

struct abkcg2fs_sb_info {
	struct path lower_root;
	u64 mount_id;
	u64 ns_inum;
	char source[PATH_MAX];
};

struct abkcg2fs_inode_info {
	struct path lower_path;
	bool shadow;
	char shadow_name[NAME_MAX];
};

struct abkcg2fs_file_info {
	struct file *lower_file;
	struct abkcg_file_ctx *abk_ctx;
	bool intercept;
	bool lower_done;
};

static const struct inode_operations abkcg2fs_dir_iops;
static const struct file_operations abkcg2fs_dir_fops;
static const struct file_operations abkcg2fs_file_fops;

static const struct fs_parameter_spec abkcg2fs_fs_parameters[] = {
	fsparam_string("source", Opt_source),
	{}
};

static inline struct abkcg2fs_inode_info *ABKCG2FS_I(struct inode *inode)
{
	return inode->i_private;
}

static inline struct abkcg2fs_sb_info *ABKCG2FS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static ssize_t abkcg2fs_emit_text(struct kiocb *iocb, struct iov_iter *to,
				  const char *text)
{
	size_t len = strlen(text);
	size_t off;
	size_t n;
	ssize_t copied;

	if (iocb->ki_pos < 0)
		return -EINVAL;

	off = min_t(size_t, iocb->ki_pos, len);
	n = min_t(size_t, iov_iter_count(to), len - off);
	copied = copy_to_iter(text + off, n, to);
	iocb->ki_pos += copied;
	return copied;
}

static struct inode *abkcg2fs_new_inode(struct super_block *sb, umode_t mode)
{
	struct abkcg2fs_inode_info *info;
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		iput(inode);
		return NULL;
	}

	inode_init_owner(&init_user_ns, inode, NULL, mode);
	inode->i_ino = get_next_ino();
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_private = info;
	if (S_ISDIR(mode)) {
		set_nlink(inode, 2);
		inode->i_op = &abkcg2fs_dir_iops;
		inode->i_fop = &abkcg2fs_dir_fops;
	} else {
		inode->i_fop = &abkcg2fs_file_fops;
	}
	return inode;
}

static void abkcg2fs_evict_inode(struct inode *inode)
{
	struct abkcg2fs_inode_info *info = ABKCG2FS_I(inode);

	clear_inode(inode);
	if (info) {
		path_put(&info->lower_path);
		kfree(info);
		inode->i_private = NULL;
	}
}

static struct inode *abkcg2fs_get_inode(struct super_block *sb, struct path *lower,
					bool shadow, const char *shadow_name)
{
	struct inode *inode;
	struct abkcg2fs_inode_info *info;
	umode_t mode = S_IFREG | 0644;

	if (shadow) {
		if (!strcmp(shadow_name, "pids.current") ||
		    !strcmp(shadow_name, "pids.peak") ||
		    !strcmp(shadow_name, "devices.list"))
			mode = S_IFREG | 0444;
		else
			mode = S_IFREG | 0644;
	} else if (lower && d_is_dir(lower->dentry)) {
		mode = S_IFDIR | 0755;
	}

	inode = abkcg2fs_new_inode(sb, mode);
	if (!inode)
		return NULL;

	info = ABKCG2FS_I(inode);
	if (lower) {
		info->lower_path = *lower;
		path_get(lower);
	}
	info->shadow = shadow;
	if (shadow_name)
		strscpy(info->shadow_name, shadow_name, sizeof(info->shadow_name));
	return inode;
}

static int abkcg2fs_proxy_open(struct inode *inode, struct file *file)
{
	struct abkcg2fs_inode_info *info = ABKCG2FS_I(inode);
	struct abkcg2fs_file_info *finfo;

	finfo = kzalloc(sizeof(*finfo), GFP_KERNEL);
	if (!finfo)
		return -ENOMEM;

	if (!info->shadow) {
		finfo->lower_file = dentry_open(&info->lower_path, file->f_flags,
						current_cred());
		if (IS_ERR(finfo->lower_file)) {
			int ret = PTR_ERR(finfo->lower_file);

			kfree(finfo);
			return ret;
		}
		if (d_is_dir(info->lower_path.dentry)) {
			finfo->abk_ctx = abkcg_ctx_from_dentry(info->lower_path.dentry, "");
		} else if (abkcg_is_intercepted_file(file->f_path.dentry->d_name.name)) {
			finfo->intercept = true;
			finfo->abk_ctx = abkcg_ctx_from_dentry(info->lower_path.dentry->d_parent,
							       file->f_path.dentry->d_name.name);
		}
	} else {
		finfo->intercept = true;
		finfo->abk_ctx = abkcg_ctx_from_dentry(info->lower_path.dentry,
						       info->shadow_name);
	}

	file->private_data = finfo;
	if (finfo->abk_ctx && IS_ERR(finfo->abk_ctx)) {
		int ret = PTR_ERR(finfo->abk_ctx);

		abkcg_ctx_put(finfo->abk_ctx);
		if (finfo->lower_file)
			fput(finfo->lower_file);
		kfree(finfo);
		return ret;
	}
	return 0;
}

static int abkcg2fs_proxy_release(struct inode *inode, struct file *file)
{
	struct abkcg2fs_file_info *finfo = file->private_data;

	if (finfo) {
		if (finfo->lower_file)
			fput(finfo->lower_file);
		abkcg_ctx_put(finfo->abk_ctx);
		kfree(finfo);
	}
	return 0;
}

static ssize_t abkcg2fs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct abkcg2fs_inode_info *info = ABKCG2FS_I(file_inode(file));
	struct abkcg2fs_file_info *finfo = file->private_data;
	if (!info->shadow && !finfo->intercept)
		return vfs_iter_read(finfo->lower_file, to, &iocb->ki_pos, 0);

	if (!info->shadow) {
		char lower[256];
		char merged[320];
		ssize_t ret;
		loff_t pos = 0;
		unsigned int ctl;
		int len = 0;

		if (!strcmp(finfo->abk_ctx->name, "cgroup.controllers")) {
			memset(lower, 0, sizeof(lower));
			ret = kernel_read(finfo->lower_file, lower, sizeof(lower) - 1, &pos);
			if (ret < 0)
				return ret;
			lower[ret] = '\0';
			while (ret > 0 && (lower[ret - 1] == '\n' || lower[ret - 1] == '\0'))
				lower[--ret] = '\0';
			ctl = abkcg_available_controllers(finfo->abk_ctx->cgrp);
			len += scnprintf(merged + len, sizeof(merged) - len, "%s", lower);
			if (ctl & ABKCG_CTL_PIDS)
				len += scnprintf(merged + len, sizeof(merged) - len, "%spids",
						 len ? " " : "");
			if (ctl & ABKCG_CTL_DEVICES)
				len += scnprintf(merged + len, sizeof(merged) - len, "%sdevices",
						 len ? " " : "");
			len += scnprintf(merged + len, sizeof(merged) - len, "\n");
			return abkcg2fs_emit_text(iocb, to, merged);
		}

		if (!strcmp(finfo->abk_ctx->name, "cgroup.subtree_control")) {
			memset(lower, 0, sizeof(lower));
			ret = kernel_read(finfo->lower_file, lower, sizeof(lower) - 1, &pos);
			if (ret < 0)
				return ret;
			lower[ret] = '\0';
			while (ret > 0 && (lower[ret - 1] == '\n' || lower[ret - 1] == '\0'))
				lower[--ret] = '\0';
			ctl = abkcg_subtree_control(finfo->abk_ctx->cgrp);
			len += scnprintf(merged + len, sizeof(merged) - len, "%s", lower);
			if (ctl & ABKCG_CTL_PIDS)
				len += scnprintf(merged + len, sizeof(merged) - len, "%spids",
						 len ? " " : "");
			if (ctl & ABKCG_CTL_DEVICES)
				len += scnprintf(merged + len, sizeof(merged) - len, "%sdevices",
						 len ? " " : "");
			len += scnprintf(merged + len, sizeof(merged) - len, "\n");
			return abkcg2fs_emit_text(iocb, to, merged);
		}

		return vfs_iter_read(finfo->lower_file, to, &iocb->ki_pos, 0);
	}

	{
		char *tmp;
		ssize_t ret;

		if (!finfo->abk_ctx || IS_ERR(finfo->abk_ctx))
			return -ENOENT;

		tmp = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;

		ret = abkcg_read_file(finfo->abk_ctx->cgrp, finfo->abk_ctx->name, tmp,
				      PAGE_SIZE, &iocb->ki_pos);
		if (ret > 0)
			ret = copy_to_iter(tmp, ret, to);

		kfree(tmp);
		return ret;
	}
}

static ssize_t abkcg2fs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct abkcg2fs_inode_info *info = ABKCG2FS_I(file_inode(file));
	struct abkcg2fs_file_info *finfo = file->private_data;

	if (!info->shadow && !finfo->intercept)
		return vfs_iter_write(finfo->lower_file, from, &iocb->ki_pos, 0);

	if (!info->shadow) {
		size_t count = iov_iter_count(from);
		char *tmp;
		char pass[256];
		int pass_len;

		if (!strcmp(finfo->abk_ctx->name, "cgroup.subtree_control")) {
			tmp = kmalloc(count + 1, GFP_KERNEL);
			if (!tmp)
				return -ENOMEM;
			if (!copy_from_iter_full(tmp, count, from)) {
				kfree(tmp);
				return -EFAULT;
			}
			tmp[count] = '\0';
			pass_len = abkcg_write_subtree_control(finfo->abk_ctx->cgrp, tmp, count,
							       pass, sizeof(pass));
			kfree(tmp);
			if (pass_len < 0)
				return pass_len;
			if (!pass_len)
				return count;
			return kernel_write(finfo->lower_file, pass, pass_len, &iocb->ki_pos);
		}

		return vfs_iter_write(finfo->lower_file, from, &iocb->ki_pos, 0);
	}

	{
		size_t count = iov_iter_count(from);
		char *tmp;
		ssize_t ret;

		if (!finfo->abk_ctx || IS_ERR(finfo->abk_ctx))
			return -ENOENT;

		tmp = kmalloc(count + 1, GFP_KERNEL);
		if (!tmp) {
			return -ENOMEM;
		}

		if (!copy_from_iter_full(tmp, count, from)) {
			kfree(tmp);
			return -EFAULT;
		}
		tmp[count] = '\0';

		ret = abkcg_write_file(finfo->abk_ctx->cgrp, finfo->abk_ctx->name, tmp, count);
		kfree(tmp);
		return ret;
	}
}

static loff_t abkcg2fs_llseek(struct file *file, loff_t offset, int whence)
{
	struct abkcg2fs_inode_info *info = ABKCG2FS_I(file_inode(file));
	struct abkcg2fs_file_info *finfo = file->private_data;

	if (!info->shadow)
		return vfs_llseek(finfo->lower_file, offset, whence);

	return default_llseek(file, offset, whence);
}

struct abkcg2fs_readdir_ctx {
	struct dir_context ctx;
	struct dir_context *caller;
	unsigned int emitted;
};

static bool abkcg2fs_filldir(struct dir_context *ctx, const char *name, int namlen,
			     loff_t offset, u64 ino, unsigned int d_type)
{
	struct abkcg2fs_readdir_ctx *rctx;

	rctx = container_of(ctx, struct abkcg2fs_readdir_ctx, ctx);
	if (!dir_emit(rctx->caller, name, namlen, ino, d_type))
		return false;

	rctx->emitted++;
	rctx->caller->pos = offset;
	return true;
}

static int abkcg2fs_iterate(struct file *file, struct dir_context *ctx)
{
	static const char * const shadow_files[] = {
		"pids.max", "pids.current", "pids.peak",
		"devices.allow", "devices.deny", "devices.list",
	};
	struct abkcg2fs_file_info *finfo = file->private_data;
	struct abkcg2fs_readdir_ctx rctx = {
		.ctx.actor = abkcg2fs_filldir,
		.caller = ctx,
	};
	unsigned int i;
	int ret;
	unsigned int ctl = abkcg_available_controllers(finfo->abk_ctx ?
						       finfo->abk_ctx->cgrp : NULL);
	unsigned int start;

	if (!finfo->lower_done) {
		ret = iterate_dir(finfo->lower_file, &rctx.ctx);
		if (ret)
			return ret;
		if (rctx.emitted)
			return 0;
		finfo->lower_done = true;
		ctx->pos = ABKCG2FS_SHADOW_POS_BASE;
	}

	start = ctx->pos - ABKCG2FS_SHADOW_POS_BASE;
	for (i = start; i < ARRAY_SIZE(shadow_files); i++) {
		if ((!strncmp(shadow_files[i], "pids.", 5) && !(ctl & ABKCG_CTL_PIDS)) ||
		    (!strncmp(shadow_files[i], "devices.", 8) && !(ctl & ABKCG_CTL_DEVICES)))
			continue;
		if (!dir_emit(ctx, shadow_files[i], strlen(shadow_files[i]),
			      get_next_ino(), DT_REG))
			break;
		ctx->pos = ABKCG2FS_SHADOW_POS_BASE + i + 1;
	}

	return 0;
}

static struct dentry *abkcg2fs_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct abkcg2fs_inode_info *parent = ABKCG2FS_I(dir);
	struct inode *inode = NULL;
	struct path lower = {};
	int ret;

	if (abkcg_is_shadow_file(dentry->d_name.name)) {
		struct abkcg_file_ctx *ctx;
		unsigned int ctl;

		ctx = abkcg_ctx_from_dentry(parent->lower_path.dentry, dentry->d_name.name);
		if (IS_ERR(ctx))
			return ERR_CAST(ctx);
		ctl = abkcg_available_controllers(ctx->cgrp);
		if ((!strncmp(dentry->d_name.name, "pids.", 5) && !(ctl & ABKCG_CTL_PIDS)) ||
		    (!strncmp(dentry->d_name.name, "devices.", 8) && !(ctl & ABKCG_CTL_DEVICES))) {
			abkcg_ctx_put(ctx);
			d_add(dentry, NULL);
			return NULL;
		}
		abkcg_ctx_put(ctx);
		inode = abkcg2fs_get_inode(dir->i_sb, &parent->lower_path, true,
					   dentry->d_name.name);
		return d_splice_alias(inode, dentry);
	}

	ret = vfs_path_lookup(parent->lower_path.dentry, parent->lower_path.mnt,
			      dentry->d_name.name, LOOKUP_FOLLOW, &lower);
	if (ret == -ENOENT) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (ret)
		return ERR_PTR(ret);

	inode = abkcg2fs_get_inode(dir->i_sb, &lower, false, NULL);
	path_put(&lower);
	return d_splice_alias(inode, dentry);
}

static int abkcg2fs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
			  struct dentry *dentry, umode_t mode)
{
	struct abkcg2fs_inode_info *parent = ABKCG2FS_I(dir);
	struct inode *lower_dir = d_inode(parent->lower_path.dentry);
	struct dentry *child;
	struct dentry *real_child = NULL;
	struct inode *inode;
	struct path lower_path;
	int ret;

	inode_lock_nested(lower_dir, I_MUTEX_PARENT);
	child = lookup_one(mnt_userns, dentry->d_name.name, parent->lower_path.dentry,
			   dentry->d_name.len);
	if (IS_ERR(child)) {
		inode_unlock(lower_dir);
		return PTR_ERR(child);
	}

	ret = vfs_mkdir(mnt_userns, lower_dir, child, mode);
	if (ret) {
		dput(child);
		inode_unlock(lower_dir);
		return ret;
	}

	if (d_unhashed(child)) {
		real_child = lookup_one(mnt_userns, dentry->d_name.name,
					parent->lower_path.dentry, dentry->d_name.len);
		if (IS_ERR(real_child)) {
			ret = PTR_ERR(real_child);
			dput(child);
			inode_unlock(lower_dir);
			return ret;
		}
		if (d_really_is_negative(real_child)) {
			dput(real_child);
			dput(child);
			inode_unlock(lower_dir);
			return -ENOENT;
		}
	} else {
		real_child = dget(child);
	}

	lower_path.mnt = parent->lower_path.mnt;
	lower_path.dentry = real_child;
	inode = abkcg2fs_get_inode(dir->i_sb, &lower_path, false, NULL);
	if (!inode) {
		dput(real_child);
		dput(child);
		inode_unlock(lower_dir);
		return -ENOMEM;
	}

	d_instantiate(dentry, inode);
	inc_nlink(dir);
	dput(real_child);
	dput(child);
	inode_unlock(lower_dir);
	return 0;
}

static int abkcg2fs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct abkcg2fs_inode_info *parent = ABKCG2FS_I(dir);
	struct inode *lower_dir = d_inode(parent->lower_path.dentry);
	struct dentry *child;
	int ret;

	inode_lock_nested(lower_dir, I_MUTEX_PARENT);
	child = lookup_one(&init_user_ns, dentry->d_name.name, parent->lower_path.dentry,
			   dentry->d_name.len);
	if (IS_ERR(child)) {
		inode_unlock(lower_dir);
		return PTR_ERR(child);
	}

	ret = vfs_rmdir(&init_user_ns, lower_dir, child);
	if (!ret)
		drop_nlink(dir);
	dput(child);
	inode_unlock(lower_dir);
	return ret;
}

static const struct inode_operations abkcg2fs_dir_iops = {
	.lookup = abkcg2fs_lookup,
	.mkdir = abkcg2fs_mkdir,
	.rmdir = abkcg2fs_rmdir,
};

static const struct file_operations abkcg2fs_dir_fops = {
	.open = abkcg2fs_proxy_open,
	.release = abkcg2fs_proxy_release,
	.iterate_shared = abkcg2fs_iterate,
	.read = generic_read_dir,
	.llseek = abkcg2fs_llseek,
};

static const struct file_operations abkcg2fs_file_fops = {
	.open = abkcg2fs_proxy_open,
	.release = abkcg2fs_proxy_release,
	.read_iter = abkcg2fs_read_iter,
	.write_iter = abkcg2fs_write_iter,
	.llseek = abkcg2fs_llseek,
};

static const struct super_operations abkcg2fs_super_ops = {
	.evict_inode = abkcg2fs_evict_inode,
	.statfs = simple_statfs,
};

static int abkcg2fs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct abkcg2fs_mount_opts *opts = fc->fs_private;
	struct abkcg2fs_sb_info *sbi;
	struct inode *inode;
	int ret;

	if (!opts->lower_root.dentry) {
		if (!fc->source)
			return -EINVAL;
		ret = kern_path(fc->source, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&opts->lower_root);
		if (ret)
			return ret;
		if (!opts->source[0])
			strscpy(opts->source, fc->source, sizeof(opts->source));
	}

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->lower_root = opts->lower_root;
	path_get(&sbi->lower_root);
	sbi->ns_inum = current->nsproxy->mnt_ns ? current->nsproxy->mnt_ns->ns.inum : 0;
	strscpy(sbi->source, opts->source, sizeof(sbi->source));

	sb->s_fs_info = sbi;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = ABKCG2FS_MAGIC;
	sb->s_op = &abkcg2fs_super_ops;
	sb->s_time_gran = 1;

	inode = abkcg2fs_get_inode(sb, &sbi->lower_root, false, NULL);
	if (!inode)
		return -ENOMEM;

	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	sbi->mount_id = abkcg_mount_registered(sbi->ns_inum, sbi->source);
	return 0;
}

static int abkcg2fs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, abkcg2fs_fill_super);
}

static int abkcg2fs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct abkcg2fs_mount_opts *opts = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, abkcg2fs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_source:
		if (opts->lower_root.dentry)
			path_put(&opts->lower_root);
		strscpy(opts->source, param->string, sizeof(opts->source));
		opt = kern_path(param->string, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&opts->lower_root);
		if (opt)
			return opt;
		if (!fc->source || !strcmp(fc->source, "none")) {
			kfree(fc->source);
			fc->source = kstrdup(param->string, GFP_KERNEL);
			if (!fc->source) {
				path_put(&opts->lower_root);
				memset(&opts->lower_root, 0, sizeof(opts->lower_root));
				return -ENOMEM;
			}
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static int abkcg2fs_parse_monolithic(struct fs_context *fc, void *data)
{
	int ret;

	ret = generic_parse_monolithic(fc, data);
	if (ret)
		return ret;

	if (!fc->source && fc->fs_private) {
		struct abkcg2fs_mount_opts *opts = fc->fs_private;

		if (opts->source[0])
			fc->source = kstrdup(opts->source, GFP_KERNEL);
	}

	return 0;
}

static void abkcg2fs_free_fc(struct fs_context *fc)
{
	struct abkcg2fs_mount_opts *opts = fc->fs_private;

	if (!opts)
		return;
	if (opts->lower_root.dentry)
		path_put(&opts->lower_root);
	kfree(opts);
}

static const struct fs_context_operations abkcg2fs_context_ops = {
	.free = abkcg2fs_free_fc,
	.parse_param = abkcg2fs_parse_param,
	.parse_monolithic = abkcg2fs_parse_monolithic,
	.get_tree = abkcg2fs_get_tree,
};

static int abkcg2fs_init_fs_context(struct fs_context *fc)
{
	struct abkcg2fs_mount_opts *opts;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	fc->fs_private = opts;
	fc->ops = &abkcg2fs_context_ops;
	return 0;
}

static void abkcg2fs_kill_sb(struct super_block *sb)
{
	struct abkcg2fs_sb_info *sbi = ABKCG2FS_SB(sb);

	abkcg_mount_unregistered(sbi->mount_id, sbi->ns_inum);
	path_put(&sbi->lower_root);
	kfree(sbi);
	kill_anon_super(sb);
}

static struct file_system_type abkcg2fs_type = {
	.name = "abkcg2fs",
	.init_fs_context = abkcg2fs_init_fs_context,
	.parameters = abkcg2fs_fs_parameters,
	.kill_sb = abkcg2fs_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

static int __init abkcg2fs_init(void)
{
	return register_filesystem(&abkcg2fs_type);
}
fs_initcall(abkcg2fs_init);

#endif
