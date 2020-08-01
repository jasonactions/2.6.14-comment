#ifndef _LINUX_FS_STRUCT_H
#define _LINUX_FS_STRUCT_H

struct dentry;
struct vfsmount;

/*进程相关的文件*/
struct fs_struct {
	/*共享这个表的进程的个数*/
	atomic_t count;
	/*用于表中字段的读写自旋锁*/
	rwlock_t lock;
	/*打开文件设置文件权限时使用的位掩码*/
	int umask;
	/*根目录、当前工作目录、模拟根目录的目录项*/
	struct dentry * root, * pwd, * altroot;
	/*根目录、当前工作目录、模拟根目录的文件系统实例*/
	struct vfsmount * rootmnt, * pwdmnt, * altrootmnt;
};

#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

extern void exit_fs(struct task_struct *);
extern void set_fs_altroot(void);
extern void set_fs_root(struct fs_struct *, struct vfsmount *, struct dentry *);
extern void set_fs_pwd(struct fs_struct *, struct vfsmount *, struct dentry *);
extern struct fs_struct *copy_fs_struct(struct fs_struct *);
extern void put_fs_struct(struct fs_struct *);

#endif /* _LINUX_FS_STRUCT_H */
