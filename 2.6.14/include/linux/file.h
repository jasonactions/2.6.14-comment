/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <asm/atomic.h>
#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * 文件描述符指针数组的下标就是fd,进程最多不能使用多余NR_OPEN个文件描述符
 * 借助dup1(),dup2(),fcntl()系统调用，两个文件描述符可以指向同一个打开的文件
 * 即数组的两个元素指向同一个打开的文件，如将标准错误文件重定向到标准输出文件
 *
 * +--------------------+
 * |fd | file描述符指针 |
 * +--------------------+
 * | 0 | file *ptr0      |------>进程的标准输入文件
 * +--------------------+
 * | 1 | file *ptr1      |------>进程的标准输出文件
 * +--------------------+
 * | 2 | file *ptr2      |------>进程的标准错误文件
 * +--------------------+
 * |...| ...            |
 * +--------------------+
 */

struct fdtable {
	/*fd指向打开的file指针数组的项数*/
	unsigned int max_fds;
	int max_fdset;
	int next_fd;
	/*
	 * 指向实际使用的文件对象指针数组，通常指向files_struct.fd_array
	 * 如果打开文件超过32个，则分配一个更大的file指针数组，并将fd指向它
	 * 同时修改max_fds的大小
	 */
	struct file ** fd;      /* current fd array */
	/*指向内嵌的close_on_exec_init*/
	fd_set *close_on_exec;
	/*指向内嵌的open_fds_init*/
	fd_set *open_fds;
	struct rcu_head rcu;
	struct files_struct *free_files;
	struct fdtable *next;
};

/*
 * Open file table structure
 */
struct files_struct {
	/*共享该表的进程数目*/
	atomic_t count;
        spinlock_t file_lock;     /* Protects all the below members.  Nests inside tsk->alloc_lock */
	/*
	 * 指向实际的打开文件表，通常指向内嵌的fdtab
	 * 如果打开文件超过32个，则分配一个更大的fdtable，并将fdt指向它
	 */
	struct fdtable *fdt;
	/*内嵌的打开文件表*/
	struct fdtable fdtab;
        /*内嵌的执行完需要关闭的文件的文件描述符的位图，由内嵌的fdtab.close_on_exec指向*/
	fd_set close_on_exec_init;
        /*内嵌的已打开文件的文件描述符的位图，内嵌的fstab.open_fds指向*/
	fd_set open_fds_init;
	/*内嵌的文件对象指针的初始化数组*/
        struct file * fd_array[NR_OPEN_DEFAULT];
};

#define files_fdtable(files) (rcu_dereference((files)->fdt))

extern void FASTCALL(__fput(struct file *));
extern void FASTCALL(fput(struct file *));

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed))
		fput(file);
}

extern struct file * FASTCALL(fget(unsigned int fd));
extern struct file * FASTCALL(fget_light(unsigned int fd, int *fput_needed));
extern void FASTCALL(set_close_on_exec(unsigned int fd, int flag));
extern void put_filp(struct file *);
extern int get_unused_fd(void);
extern void FASTCALL(put_unused_fd(unsigned int fd));
struct kmem_cache_s;
extern void filp_ctor(void * objp, struct kmem_cache_s *cachep, unsigned long cflags);
extern void filp_dtor(void * objp, struct kmem_cache_s *cachep, unsigned long dflags);

extern struct file ** alloc_fd_array(int);
extern void free_fd_array(struct file **, int);

extern fd_set *alloc_fdset(int);
extern void free_fdset(fd_set *, int);

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable(struct fdtable *fdt);
extern void __init files_defer_init(void);

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference(fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

extern void FASTCALL(fd_install(unsigned int fd, struct file * file));

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void FASTCALL(put_files_struct(struct files_struct *fs));

#endif /* __LINUX_FILE_H */
