#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/mount.h>
#include <linux/sched.h>

/*进程所拥有的已安装文件系统树*/
struct namespace {
	/*共享命名空间的进程数*/
	atomic_t		count;
	/*
	 * 命名空间根目录的已安装文件系统描述符
	 * 它是这个命名空间已安装文件系统的根
	 * 进程可以通过pivot_root系统调用来改变它的命名空间的根文件系统
	 */
	struct vfsmount *	root;
	/*属于命名空间的所有已安装文件系统的链表头*/
	struct list_head	list;
	struct rw_semaphore	sem;
};

extern int copy_namespace(int, struct task_struct *);
extern void __put_namespace(struct namespace *namespace);

static inline void put_namespace(struct namespace *namespace)
{
	if (atomic_dec_and_lock(&namespace->count, &vfsmount_lock))
		/* releases vfsmount_lock */
		__put_namespace(namespace);
}

static inline void exit_namespace(struct task_struct *p)
{
	struct namespace *namespace = p->namespace;
	if (namespace) {
		task_lock(p);
		p->namespace = NULL;
		task_unlock(p);
		put_namespace(namespace);
	}
}

static inline void get_namespace(struct namespace *namespace)
{
	atomic_inc(&namespace->count);
}

#endif
#endif
