/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/*已安装文件系统中禁止setuid和setgid标志*/
#define MNT_NOSUID	1
/*在已安装文件系统中禁止访问设备文件*/
#define MNT_NODEV	2
/*在已安装文件系统中不允许程序执行*/
#define MNT_NOEXEC	4

/*代表文件系统的实例*/
struct vfsmount
{
	/*用于散列表的链接件*/
	struct list_head mnt_hash;
	/*指向父文件系统实例对应的vfsmount*/
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	/*指向当前文件系统实例安装目录的dentry*/
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	/*指向当前文件系统实例根目录的dentry*/
	struct dentry *mnt_root;	/* root of the mounted tree */
	/*指向当前文件系统实例的superblock*/
	struct super_block *mnt_sb;	/* pointer to superblock */
	/*安装在当前文件系统实例所有目录下的所有文件系统实例链表的表头*/
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/*链接到父文件系统实例的子文件系统实例链表的链接件*/
	struct list_head mnt_child;	/* and going through their mnt_child */
	/*使用计数器*/
	atomic_t mnt_count;
	/*装载标志*/
	int mnt_flags;
	/*如果为1，表示当前文件系统实例已过期*/
	int mnt_expiry_mark;		/* true if marked for expiry */
	/*存放文件系统的块设备的设备名*/
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	/*链接到所属namespace的文件系统实例链表的链接件*/
	struct list_head mnt_list;
	/*链接到过期文件系统实例链表的链接件*/
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	/*指向安装了当前文件系统实例的进程namespace的指针*/
	struct namespace *mnt_namespace; /* containing namespace */
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

extern void __mntput(struct vfsmount *mnt);

static inline void mntput_no_expire(struct vfsmount *mnt)
{
	if (mnt) {
		if (atomic_dec_and_test(&mnt->mnt_count))
			__mntput(mnt);
	}
}

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern void free_vfsmnt(struct vfsmount *mnt);
extern struct vfsmount *alloc_vfsmnt(const char *name);
extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct nameidata;

extern int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif
#endif /* _LINUX_MOUNT_H */
