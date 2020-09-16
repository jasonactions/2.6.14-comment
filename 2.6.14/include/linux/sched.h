#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <asm/param.h>	/* for HZ */

#include <linux/config.h>
#include <linux/capability.h>
#include <linux/threads.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/rbtree.h>
#include <linux/thread_info.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/nodemask.h>

#include <asm/system.h>
#include <asm/semaphore.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/mmu.h>
#include <asm/cputime.h>

#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/signal.h>
#include <linux/securebits.h>
#include <linux/fs_struct.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/pid.h>
#include <linux/percpu.h>
#include <linux/topology.h>
#include <linux/seccomp.h>

#include <linux/auxvec.h>	/* For AT_VECTOR_SIZE */

struct exec_domain;

/*
 * cloning flags:
 */
/*
 * 低字节指定子进程结束时发送给父进程的信号代码，一般为SIGCHLD信号
 * 剩余3字节给一clone标志组用于编码
 */
#define CSIGNAL		0x000000ff	/* signal mask to be sent at exit */
 /*共享内存描述符和所有的页表*/ 
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
/*共享根目录和当前工作目录*/
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
/*共享打开文件表*/
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
/*共享信号处理程序表、阻塞信号表和挂起信号表*/
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers and blocked signals shared */
/*如果父进程被跟踪，子进程也被跟踪*/
#define CLONE_PTRACE	0x00002000	/* set if we want to let tracing continue on the child too */
/*vfork系统调用时设置*/
#define CLONE_VFORK	0x00004000	/* set if the parent wants the child to wake it up on mm_release */
/*设置子进程的父进程为调用进程的父进程*/
#define CLONE_PARENT	0x00008000	/* set if we want to have the same parent as the cloner */
/*把子进程插入到父进程同一线程组中，并迫使子进程共享父进程的信号描述符，此标志为true则必须设置CLONE_SIGHAND*/
#define CLONE_THREAD	0x00010000	/* Same thread group? */
/*当clone需要自己的命名空间（即子进程自己的已挂载文件系统视图）时设置这个标志*/
#define CLONE_NEWNS	0x00020000	/* New namespace group? */
/*共享System V IPC取消信号量的操作*/
#define CLONE_SYSVSEM	0x00040000	/* share system V SEM_UNDO semantics */
/*为轻量级进程创建新的线程局部存储段（TLS），该段由参数tls所指向的结构进行描述*/
#define CLONE_SETTLS	0x00080000	/* create a new TLS for the child */
/*把子进程的PID写入父进程由ptid参数指向的用户态变量*/
#define CLONE_PARENT_SETTID	0x00100000	/* set the TID in the parent */
/*
 * 如果该标志被设置，则内核建立一种触发机制，用在子进程要退出或要开始执行新程序时
 * 这些情况下，内核将消除由参数ctid所指向的用户态变量，并唤醒等待这个事件的任何进程
 */
#define CLONE_CHILD_CLEARTID	0x00200000	/* clear the TID in the child */
/*遗留标志，内核忽略*/
#define CLONE_DETACHED		0x00400000	/* Unused, ignored */
/*设置这个标志使得CLONE_PTRACE标志失去作用*/
#define CLONE_UNTRACED		0x00800000	/* set if the tracing process can't force CLONE_PTRACE on this clone */
/*把子进程的PID写入由ctid参数所指向的子进程的用户态变量中*/
#define CLONE_CHILD_SETTID	0x01000000	/* set the TID in the child */
/*强迫子进程开始于TASK_STOPPED状态*/
#define CLONE_STOPPED		0x02000000	/* Start in stopped state */

/*
 * List of flags we want to share for kernel threads,
 * if only because they are not used by them anyway.
 */
#define CLONE_KERNEL	(CLONE_FS | CLONE_FILES | CLONE_SIGHAND)

/*
 * These are the constant used to fake the fixed-point load-average
 * counting. Some notes:
 *  - 11 bit fractions expand to 22 bits by the multiplies: this gives
 *    a load-average precision of 10 bits integer + 11 bits fractional
 *  - if you want to count load-averages more often, you need more
 *    precision, or rounding will get you. With 2-second counting freq,
 *    the EXP_n values would be 1981, 2034 and 2043 if still using only
 *    11 bit fractions.
 */
extern unsigned long avenrun[];		/* Load averages */

#define FSHIFT		11		/* nr of bits of precision */
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#define LOAD_FREQ	(5*HZ)		/* 5 sec intervals */
#define EXP_1		1884		/* 1/exp(5sec/1min) as fixed-point */
#define EXP_5		2014		/* 1/exp(5sec/5min) */
#define EXP_15		2037		/* 1/exp(5sec/15min) */

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;

extern unsigned long total_forks;
extern int nr_threads;
extern int last_pid;
DECLARE_PER_CPU(unsigned long, process_counts);
extern int nr_processes(void);
extern unsigned long nr_running(void);
extern unsigned long nr_uninterruptible(void);
extern unsigned long nr_iowait(void);

#include <linux/time.h>
#include <linux/param.h>
#include <linux/resource.h>
#include <linux/timer.h>

#include <asm/processor.h>

/*
 * Task state bitmask. NOTE! These bits are also
 * encoded in fs/proc/array.c: get_task_state().
 *
 * We have two separate sets of flags: task->state
 * is about runnability, while task->exit_state are
 * about the task exiting. Confusing, but this way
 * modifying one set can't modify the other one by
 * mistake.
 */
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_STOPPED		4
#define TASK_TRACED		8
/* in tsk->exit_state */
#define EXIT_ZOMBIE		16
#define EXIT_DEAD		32
/* in tsk->state again */
#define TASK_NONINTERACTIVE	64

#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))

/*
 * set_current_state() includes a barrier so that the write of current->state
 * is correctly serialised wrt the caller's subsequent test of whether to
 * actually sleep:
 *
 *	set_current_state(TASK_UNINTERRUPTIBLE);
 *	if (do_i_need_to_sleep())
 *		schedule();
 *
 * If the caller does not need such serialisation then use __set_current_state()
 */
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))

/* Task command name length */
#define TASK_COMM_LEN 16

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2

struct sched_param {
	int sched_priority;
};

#ifdef __KERNEL__

#include <linux/spinlock.h>

/*
 * This serializes "schedule()" and also protects
 * the run-queue from deletions/modifications (but
 * _adding_ to the beginning of the run-queue has
 * a separate lock).
 */
extern rwlock_t tasklist_lock;
extern spinlock_t mmlist_lock;

typedef struct task_struct task_t;

extern void sched_init(void);
extern void sched_init_smp(void);
extern void init_idle(task_t *idle, int cpu);

extern cpumask_t nohz_cpu_mask;

extern void show_state(void);
extern void show_regs(struct pt_regs *);

/*
 * TASK is a pointer to the task whose backtrace we want to see (or NULL for current
 * task), SP is the stack pointer of the first frame that should be shown in the back
 * trace (or NULL if the entire call-chain of the task should be shown).
 */
extern void show_stack(struct task_struct *task, unsigned long *sp);

void io_schedule(void);
long io_schedule_timeout(long timeout);

extern void cpu_init (void);
extern void trap_init(void);
extern void update_process_times(int user);
extern void scheduler_tick(void);

#ifdef CONFIG_DETECT_SOFTLOCKUP
extern void softlockup_tick(struct pt_regs *regs);
extern void spawn_softlockup_task(void);
extern void touch_softlockup_watchdog(void);
#else
static inline void softlockup_tick(struct pt_regs *regs)
{
}
static inline void spawn_softlockup_task(void)
{
}
static inline void touch_softlockup_watchdog(void)
{
}
#endif


/* Attach to any functions which should be ignored in wchan output. */
#define __sched		__attribute__((__section__(".sched.text")))
/* Is this address in the __sched functions? */
extern int in_sched_functions(unsigned long addr);

#define	MAX_SCHEDULE_TIMEOUT	LONG_MAX
extern signed long FASTCALL(schedule_timeout(signed long timeout));
extern signed long schedule_timeout_interruptible(signed long timeout);
extern signed long schedule_timeout_uninterruptible(signed long timeout);
asmlinkage void schedule(void);

struct namespace;

/* Maximum number of active map areas.. This is a random (large) number */
#define DEFAULT_MAX_MAP_COUNT	65536

extern int sysctl_max_map_count;

#include <linux/aio.h>

extern unsigned long
arch_get_unmapped_area(struct file *, unsigned long, unsigned long,
		       unsigned long, unsigned long);
extern unsigned long
arch_get_unmapped_area_topdown(struct file *filp, unsigned long addr,
			  unsigned long len, unsigned long pgoff,
			  unsigned long flags);
extern void arch_unmap_area(struct mm_struct *, unsigned long);
extern void arch_unmap_area_topdown(struct mm_struct *, unsigned long);

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
/*
 * The mm counters are not protected by its page_table_lock,
 * so must be incremented atomically.
 */
#ifdef ATOMIC64_INIT
#define set_mm_counter(mm, member, value) atomic64_set(&(mm)->_##member, value)
#define get_mm_counter(mm, member) ((unsigned long)atomic64_read(&(mm)->_##member))
#define add_mm_counter(mm, member, value) atomic64_add(value, &(mm)->_##member)
#define inc_mm_counter(mm, member) atomic64_inc(&(mm)->_##member)
#define dec_mm_counter(mm, member) atomic64_dec(&(mm)->_##member)
typedef atomic64_t mm_counter_t;
#else /* !ATOMIC64_INIT */
/*
 * The counters wrap back to 0 at 2^32 * PAGE_SIZE,
 * that is, at 16TB if using 4kB page size.
 */
#define set_mm_counter(mm, member, value) atomic_set(&(mm)->_##member, value)
#define get_mm_counter(mm, member) ((unsigned long)atomic_read(&(mm)->_##member))
#define add_mm_counter(mm, member, value) atomic_add(value, &(mm)->_##member)
#define inc_mm_counter(mm, member) atomic_inc(&(mm)->_##member)
#define dec_mm_counter(mm, member) atomic_dec(&(mm)->_##member)
typedef atomic_t mm_counter_t;
#endif /* !ATOMIC64_INIT */

#else  /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */
/*
 * The mm counters are protected by its page_table_lock,
 * so can be incremented directly.
 */
#define set_mm_counter(mm, member, value) (mm)->_##member = (value)
#define get_mm_counter(mm, member) ((mm)->_##member)
#define add_mm_counter(mm, member, value) (mm)->_##member += (value)
#define inc_mm_counter(mm, member) (mm)->_##member++
#define dec_mm_counter(mm, member) (mm)->_##member--
typedef unsigned long mm_counter_t;

#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

#define get_mm_rss(mm)					\
	(get_mm_counter(mm, file_rss) + get_mm_counter(mm, anon_rss))
#define update_hiwater_rss(mm)	do {			\
	unsigned long _rss = get_mm_rss(mm);		\
	if ((mm)->hiwater_rss < _rss)			\
		(mm)->hiwater_rss = _rss;		\
} while (0)
#define update_hiwater_vm(mm)	do {			\
	if ((mm)->hiwater_vm < (mm)->total_vm)		\
		(mm)->hiwater_vm = (mm)->total_vm;	\
} while (0)

/*内存描述符，描述与进程地址空间有关的全部信息,init_mm是进程0所使用的内存描述符*/
struct mm_struct {
	/*指向线性区对象的链表头*/
	struct vm_area_struct * mmap;		/* list of VMAs */
	/*指向线性区对象的红-黑树的根*/
	struct rb_root mm_rb;
	/*指向最后一次引用的线性区对象*/
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	/*
	 * 在进程地址空间搜索有效线性地址区间的方法
	 * 根据进程线性区类型，有两种：arch_get_unmapped_area和arch_get_unmapped_area_top_down
	 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	/*释放线性地址区间时调用的方法*/
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
	/*标示第一个分配的匿名线性区或文件内存映射的线性地址*/
        unsigned long mmap_base;		/* base of mmap area */
	/*刚刚访问vma空洞,空洞是指位于vma之间的未映射区域*/
        unsigned long cached_hole_size;         /* if non-zero, the largest hole below free_area_cache */
	/*
	 * 最近被分配的线性区的结束地址，初始化为用户态线性地址空间的1/3(1G,0x4000 0000)
	 * 注：用户态线性地址空间的1/3为预定义起始地址线性区，典型为text段，data段，bss段保留
	 * 内核从这个地址开始搜索进程地址空间中线性地址的空闲区间
	 */
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */
	/*指向页全局目录*/
	pgd_t * pgd;
	/*
	 * 次使用计数器,存放共享mm_struct数据结构的轻量级进程的个数，如clone,fork及vfork
	 * 如果要确保mm_struct不被释放，则增加mm_users，保证mm_count不变为0
	 */
	atomic_t mm_users;			/* How many users with user space? */
	/*主使用计数器, 如果两个轻量级进程共享内存描述符，计数算为1，如果其它内核线程访问则增加1,mm_count为0则释放*/
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/*进程线性区的个数,最多65536，可通过/proc/sys/vm/max_map_count修改*/
	int map_count;				/* number of VMAs */
	/*线性区的读/写信号量*/
	struct rw_semaphore mmap_sem;
	/*线性区和页表自旋锁*/
	spinlock_t page_table_lock;		/* Protects page tables and some counters */

	/*所有内存描述符放入双向链表中，此指向内存描述符链表的连接件*/
	struct list_head mmlist;		/* List of maybe swapped mm's.  These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	mm_counter_t _file_rss;
	mm_counter_t _anon_rss;

	/*进程所拥有的最大页框数*/
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/*进程线性区中的最大页数*/
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	/*进程地址空间大小（页数）；锁住不能换出的页数；共享文件内存映射页框数；可执行内存映射中的页数*/
	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	/*用户态堆栈页数；在保留区中的页数或特殊线性区的页数；线性区默认访问标志；this进程页表项数*/
	unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
	/*可执行代码的起始/结束地址；已初始化数据的起始/结束地址*/
	unsigned long start_code, end_code, start_data, end_data;
	/*堆的起始地址/当前地址;用户态栈的起始地址*/
	unsigned long start_brk, brk, start_stack;
	/*命令行参数的起始地址/结束地址；环境变量的起始/结束地址*/
	unsigned long arg_start, arg_end, env_start, env_end;

	/*开始执行elf程序时使用*/
	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	/*表示是否可以产生内存信息转储的标志*/
	unsigned dumpable:2;
	/*用于懒惰TLB交换的位掩码???*/
	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	/*指向有关特定体系结构信息的表*/
	mm_context_t context;

	/* Token based thrashing protection. */
	/*进程在这个时间将有资格获取交换标记*/
	unsigned long swap_token_time;
	/*如果最近发生了主缺页，则设置该标志*/
	char recent_pagein;

	/* coredumping support */
	/*正在把进程地址空间的内容卸载到转储文件中的轻量级进程的数量*/
	int core_waiters;
	/*指向创建内存转储文件时的补充原语;创建内存转储文件时的补充原语*/
	struct completion *core_startup_done, core_done;

	/* aio bits */
	/*用于保护异步IO上下文链表的锁*/
	rwlock_t		ioctx_list_lock;
	/*异步IO上下文链表*/
	struct kioctx		*ioctx_list;
	/*默认的异步IO上下文*/
	struct kioctx		default_kioctx;
};

struct sighand_struct {
	atomic_t		count;
	struct k_sigaction	action[_NSIG];
	spinlock_t		siglock;
};

/*
 * NOTE! "signal_struct" does not have it's own
 * locking, because a shared signal_struct always
 * implies a shared sighand_struct, so locking
 * sighand_struct is always a proper superset of
 * the locking of signal_struct.
 */
struct signal_struct {
	atomic_t		count;
	atomic_t		live;

	wait_queue_head_t	wait_chldexit;	/* for wait4() */

	/* current thread group signal load-balancing target: */
	task_t			*curr_target;

	/* shared signal handling: */
	struct sigpending	shared_pending;

	/* thread group exit support */
	int			group_exit_code;
	/* overloaded:
	 * - notify group_exit_task when ->count is equal to notify_count
	 * - everyone except group_exit_task is stopped during signal delivery
	 *   of fatal signals, group_exit_task processes the signal.
	 */
	struct task_struct	*group_exit_task;
	int			notify_count;

	/* thread group stop support, overloads group_exit_code too */
	int			group_stop_count;
	unsigned int		flags; /* see SIGNAL_* flags below */

	/* POSIX.1b Interval Timers */
	struct list_head posix_timers;

	/* ITIMER_REAL timer for the process */
	struct timer_list real_timer;
	unsigned long it_real_value, it_real_incr;

	/* ITIMER_PROF and ITIMER_VIRTUAL timers for the process */
	cputime_t it_prof_expires, it_virt_expires;
	cputime_t it_prof_incr, it_virt_incr;

	/* job control IDs */
	/*P所在进程组的领头进程*/
	pid_t pgrp;
	pid_t tty_old_pgrp;
	/*P的登陆会话领头进程的PID*/
	pid_t session;
	/* boolean value for session group leader */
	int leader;

	struct tty_struct *tty; /* NULL if no tty */

	/*
	 * Cumulative resource counters for dead threads in the group,
	 * and for reaped dead child processes forked by this group.
	 * Live threads maintain their own counters and add to these
	 * in __exit_signal, except for the group leader.
	 */
	cputime_t utime, stime, cutime, cstime;
	unsigned long nvcsw, nivcsw, cnvcsw, cnivcsw;
	unsigned long min_flt, maj_flt, cmin_flt, cmaj_flt;

	/*
	 * Cumulative ns of scheduled CPU time for dead threads in the
	 * group, not including a zombie group leader.  (This only differs
	 * from jiffies_to_ns(utime + stime) if sched_clock uses something
	 * other than jiffies.)
	 */
	unsigned long long sched_time;

	/*
	 * We don't bother to synchronize most readers of this at all,
	 * because there is no reader checking a limit that actually needs
	 * to get both rlim_cur and rlim_max atomically, and either one
	 * alone is a single word that can safely be read normally.
	 * getrlimit/setrlimit use task_lock(current->group_leader) to
	 * protect this instead of the siglock, because they really
	 * have no need to disable irqs.
	 */
	/*当前进程的资源限制*/
	struct rlimit rlim[RLIM_NLIMITS];

	struct list_head cpu_timers[3];

	/* keep the process-shared keyrings here so that they do the right
	 * thing in threads created with CLONE_THREAD */
#ifdef CONFIG_KEYS
	struct key *session_keyring;	/* keyring inherited over fork */
	struct key *process_keyring;	/* keyring private to this process */
#endif
};

/* Context switch must be unlocked if interrupts are to be enabled */
#ifdef __ARCH_WANT_INTERRUPTS_ON_CTXSW
# define __ARCH_WANT_UNLOCKED_CTXSW
#endif

/*
 * Bits in flags field of signal_struct.
 */
#define SIGNAL_STOP_STOPPED	0x00000001 /* job control stop in effect */
#define SIGNAL_STOP_DEQUEUED	0x00000002 /* stop signal dequeued */
#define SIGNAL_STOP_CONTINUED	0x00000004 /* SIGCONT since WCONTINUED reap */
#define SIGNAL_GROUP_EXIT	0x00000008 /* group exit in progress */


/*
 * Priority of a process goes from 0..MAX_PRIO-1, valid RT
 * priority is 0..MAX_RT_PRIO-1, and SCHED_NORMAL tasks are
 * in the range MAX_RT_PRIO..MAX_PRIO-1. Priority values
 * are inverted: lower p->prio value means higher priority.
 *
 * The MAX_USER_RT_PRIO value allows the actual maximum
 * RT priority to be separate from the value exported to
 * user-space.  This allows kernel threads to set their
 * priority to a value higher than any user task. Note:
 * MAX_RT_PRIO must not be smaller than MAX_USER_RT_PRIO.
 */

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO

#define MAX_PRIO		(MAX_RT_PRIO + 40)

#define rt_task(p)		(unlikely((p)->prio < MAX_RT_PRIO))

/*
 * Some day this will be a full-fledged user tracking system..
 */
struct user_struct {
	atomic_t __count;	/* reference count */
	atomic_t processes;	/* How many processes does this user have? */
	atomic_t files;		/* How many open files does this user have? */
	atomic_t sigpending;	/* How many pending signals does this user have? */
#ifdef CONFIG_INOTIFY
	atomic_t inotify_watches; /* How many inotify watches does this user have? */
	atomic_t inotify_devs;	/* How many inotify devs does this user have opened? */
#endif
	/* protected by mq_lock	*/
	unsigned long mq_bytes;	/* How many bytes can be allocated to mqueue? */
	unsigned long locked_shm; /* How many pages of mlocked shm ? */

#ifdef CONFIG_KEYS
	struct key *uid_keyring;	/* UID specific keyring */
	struct key *session_keyring;	/* UID's default session keyring */
#endif

	/* Hash table maintenance information */
	struct list_head uidhash_list;
	uid_t uid;
};

extern struct user_struct *find_user(uid_t);

extern struct user_struct root_user;
#define INIT_USER (&root_user)

typedef struct prio_array prio_array_t;
struct backing_dev_info;
struct reclaim_state;

#ifdef CONFIG_SCHEDSTATS
struct sched_info {
	/* cumulative counters */
	unsigned long	cpu_time,	/* time spent on the cpu */
			run_delay,	/* time spent waiting on a runqueue */
			pcnt;		/* # of timeslices run on this cpu */

	/* timestamps */
	unsigned long	last_arrival,	/* when we last ran on a cpu */
			last_queued;	/* when we were last queued to run */
};

extern struct file_operations proc_schedstat_operations;
#endif

enum idle_type
{
	/*CPU当前空闲，current是swapper进程*/
	SCHED_IDLE,
	/*CPU当前空闲，current是swapper进程*/
	NOT_IDLE,
	NEWLY_IDLE,
	MAX_IDLE_TYPES
};

/*
 * sched-domains (multiprocessor balancing) declarations:
 */
#ifdef CONFIG_SMP
#define SCHED_LOAD_SCALE	128UL	/* increase resolution of load */

#define SD_LOAD_BALANCE		1	/* Do load balancing on this domain. */
#define SD_BALANCE_NEWIDLE	2	/* Balance when about to become idle */
#define SD_BALANCE_EXEC		4	/* Balance on exec */
#define SD_BALANCE_FORK		8	/* Balance on fork, clone */
#define SD_WAKE_IDLE		16	/* Wake to idle CPU on task wakeup */
#define SD_WAKE_AFFINE		32	/* Wake task to waking CPU */
#define SD_WAKE_BALANCE		64	/* Perform balancing at task wakeup */
#define SD_SHARE_CPUPOWER	128	/* Domain members share cpu power */

/*调度组*/
struct sched_group {
	struct sched_group *next;	/* Must be a circular list */
	cpumask_t cpumask;

	/*
	 * CPU power of this group, SCHED_LOAD_SCALE being max power for a
	 * single CPU. This is read only (except for setup, hotplug CPU).
	 */
	unsigned long cpu_power;
};

/*
 * 调度域，由调度组组成
 * refs: https://lwn.net/Articles/80911/
 *       https://www.ibm.com/developerworks/cn/linux/l-cn-schldom/
 */
struct sched_domain {
	/* These fields must be setup */
	struct sched_domain *parent;	/* top domain must be null terminated */
	/*指向调度组链表的第一个元素*/
	struct sched_group *groups;	/* the balancing groups of the domain */
	cpumask_t span;			/* span of all CPUs in this domain */
	unsigned long min_interval;	/* Minimum balance interval ms */
	unsigned long max_interval;	/* Maximum balance interval ms */
	unsigned int busy_factor;	/* less balancing by factor if busy */
	unsigned int imbalance_pct;	/* No balance until over watermark */
	unsigned long long cache_hot_time; /* Task considered cache hot (ns) */
	unsigned int cache_nice_tries;	/* Leave cache hot tasks for # tries */
	unsigned int per_cpu_gain;	/* CPU % gained by adding domain cpus */
	unsigned int busy_idx;
	unsigned int idle_idx;
	unsigned int newidle_idx;
	unsigned int wake_idx;
	unsigned int forkexec_idx;
	int flags;			/* See SD_* */

	/* Runtime fields. */
	unsigned long last_balance;	/* init to jiffies. units in jiffies */
	unsigned int balance_interval;	/* initialise to 1. units in ms. */
	unsigned int nr_balance_failed; /* initialise to 0 */

#ifdef CONFIG_SCHEDSTATS
	/* load_balance() stats */
	unsigned long lb_cnt[MAX_IDLE_TYPES];
	unsigned long lb_failed[MAX_IDLE_TYPES];
	unsigned long lb_balanced[MAX_IDLE_TYPES];
	unsigned long lb_imbalance[MAX_IDLE_TYPES];
	unsigned long lb_gained[MAX_IDLE_TYPES];
	unsigned long lb_hot_gained[MAX_IDLE_TYPES];
	unsigned long lb_nobusyg[MAX_IDLE_TYPES];
	unsigned long lb_nobusyq[MAX_IDLE_TYPES];

	/* Active load balancing */
	unsigned long alb_cnt;
	unsigned long alb_failed;
	unsigned long alb_pushed;

	/* SD_BALANCE_EXEC stats */
	unsigned long sbe_cnt;
	unsigned long sbe_balanced;
	unsigned long sbe_pushed;

	/* SD_BALANCE_FORK stats */
	unsigned long sbf_cnt;
	unsigned long sbf_balanced;
	unsigned long sbf_pushed;

	/* try_to_wake_up() stats */
	unsigned long ttwu_wake_remote;
	unsigned long ttwu_move_affine;
	unsigned long ttwu_move_balance;
#endif
};

extern void partition_sched_domains(cpumask_t *partition1,
				    cpumask_t *partition2);
#endif /* CONFIG_SMP */


struct io_context;			/* See blkdev.h */
void exit_io_context(void);
struct cpuset;

#define NGROUPS_SMALL		32
#define NGROUPS_PER_BLOCK	((int)(PAGE_SIZE / sizeof(gid_t)))
struct group_info {
	int ngroups;
	atomic_t usage;
	gid_t small_block[NGROUPS_SMALL];
	int nblocks;
	gid_t *blocks[0];
};

/*
 * get_group_info() must be called with the owning task locked (via task_lock())
 * when task != current.  The reason being that the vast majority of callers are
 * looking at current->group_info, which can not be changed except by the
 * current task.  Changing current->group_info requires the task lock, too.
 */
#define get_group_info(group_info) do { \
	atomic_inc(&(group_info)->usage); \
} while (0)

#define put_group_info(group_info) do { \
	if (atomic_dec_and_test(&(group_info)->usage)) \
		groups_free(group_info); \
} while (0)

extern struct group_info *groups_alloc(int gidsetsize);
extern void groups_free(struct group_info *group_info);
extern int set_current_groups(struct group_info *group_info);
extern int groups_search(struct group_info *group_info, gid_t grp);
/* access the groups "array" with this macro */
#define GROUP_AT(gi, i) \
    ((gi)->blocks[(i)/NGROUPS_PER_BLOCK][(i)%NGROUPS_PER_BLOCK])

#ifdef ARCH_HAS_PREFETCH_SWITCH_STACK
extern void prefetch_stack(struct task_struct*);
#else
static inline void prefetch_stack(struct task_struct *t) { }
#endif

struct audit_context;		/* See audit.c */
struct mempolicy;

/*进程描述符*/
struct task_struct {
	/*
	 * 进程的当前状态：
	 * .TASK_RUNNING
	 *     进程要么在CPU上执行，要么准备执行
	 * .TASK_INTERRUPTIBLE
	 *     进程被挂起，中断、资源满足、传递信号都可以唤醒进程,进程状态修改为TASK_RUNNING
	 * .TASK_UNINTERRUPTIBLE
	 *     不能被异步信号打断的挂起状态, 对于不可中断的执行流程会用到这个状态
	 * .TASK_STOPPED
	 *     进程的执行被暂停。当进程收到SIGSTOP,SIGTSTP,SIGTTIN,SIGTTOU信号会暂停
	 * .TASK_TRACED
	 *     进程的执行已由debugger程序暂停。
	 */
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	struct thread_info *thread_info;
	atomic_t usage;
	unsigned long flags;	/* per process flags, defined below */
	unsigned long ptrace;

	int lock_depth;		/* BKL lock depth */

#if defined(CONFIG_SMP) && defined(__ARCH_WANT_UNLOCKED_CTXSW)
	int oncpu;
#endif
	/*
	 * -static_prio:进程的静态优先级
	 * (1)NORMAL进程静态优先级
	 *     用于计算进程的时间片,普通进程（100~139）值越大静态优先级越低
	 *     新进程继承其父进程的静态优先级,通过nice()/setpriority()系统调用，用户可以改变拥有的进程的静态优先级
	 *                           / (140-静态优先级) x 20， 静态优先级<120
	 *     基本时间片（单位ms）= 
	 *                           \ (140-静态优先级) x 5,   静态优先级>=120
	 * (2)RR进程的静态优先级
	 *     基本时间片计算同普通进程
	 * (3)FIFO进程无静态优先级
	 *
	 * -prio:进程的动态优先级
	 * (1)NORMAL进程动态优先级
	 *     作为调度器选择合适的进程的依据,普通进程（100~139）值越大静态优先级越低
	 *
	 *     动态优先级 = max(100, min(静态优先级 - bonus + 5, 139)), 0 =<bonus<= 10
	 *     注：bonus大于5表示增加动态优先级奖励；小于5表示减少优先级惩罚
	 *         bonus依赖于平均睡眠时间（进程在睡眠状态所消耗的平均纳秒数）
	 * (2)RR进程和FIFO进程动态优先级与它们的实时优先级成线性，不随进程的运行而改变
	 */
	int prio, static_prio;
	/*
	 * 每个进程优先级都对应一个链表，当前进程将根据优先级不同链入不同的优先级链表
	 * 如当前进程优先级为k(0~139),将链入优先级为k的可运行进程链表中
	 * 在多处理器系统中，每个CPU有自己的运行队列(优先级链表集)
	 */
	struct list_head run_list;
	/*指向包含进程的运行队列的集合*/
	prio_array_t *array;

	unsigned short ioprio;

	/*进程的平均睡眠时间，会影响NORMAL进程的动态优先级*/
	unsigned long sleep_avg;
	/*
	 * timestamp: 导致进程进入睡眠状态的进程切换的时间戳 或 进程最近插入运行队列的时间
	 * last_ran：最近一次替换本进程的进程切换时间
	 */
	unsigned long long timestamp, last_ran;
	unsigned long long sched_time; /* sched_clock time spent running */
	/*
	 * 进程被唤醒时使用的条件代码
	 * 0:  进程处于TASK_RUNNING状态
	 * 1:  进程处于TASK_INTERRUPTABLE或TASK_STOPPED状态，而且正在被系统调用服务例程或内核线程唤醒
	 * 2： 进程处于TASK_INTERRUPTABLE或TASK_STOPPED状态，而且正在被中断处理程序或可延迟函数唤醒
	 * -1: 进程处于TASK_UNINTERRUPTABLE状态而且正在被唤醒
	 */
	int activated;

	/*进程的调度类型（SCHED_NORMAL,SCHED_RR或SCHED_FIFO）*/
	unsigned long policy;
	/*能执行进程的CPU位掩码*/
	cpumask_t cpus_allowed;
	/*
	 * time_slice:在进程的时间片中还剩余的时钟节拍数
	 * first_time_slice: 如果进程肯定不会用完其时间片，就把该标志设置为1
	 */
	unsigned int time_slice, first_time_slice;

#ifdef CONFIG_SCHEDSTATS
	struct sched_info sched_info;
#endif

	struct list_head tasks;
	/*
	 * ptrace_list/ptrace_children forms the list of my children
	 * that were stolen by a ptracer.
	 */
	/*包含所有被debugger跟踪的P的子进程的链表头*/
	struct list_head ptrace_children;
	/*链入P的父进程所有被debugger跟踪的子进程的链表的链接件*/
	struct list_head ptrace_list;

	/*
	 * mm为进程拥有的内存描述符，active_mm为进程运行时使用的描述符
	 * 对普通进程两者相同，对内核线程mm为NULL，表示不拥有任何内存描述符
	 * 内核线程将active_mm初始化为前一个运行进程的active_mm
	 */
	struct mm_struct *mm, *active_mm;

/* task state */
	struct linux_binfmt *binfmt;
	/*
	 * 进程的退出状态：
	 * .EXIT_ZOMBLE
	 *     进程的执行被终止，但父进程还没有发布wait4()或waitpid()系统调用来返回有关死亡进程的信息,因此进程描述符还没释放
	 * .EXIT_DEAD
	 *     由于父进程刚发出wait4()或waitpid()系统调用，因此进程由系统删除。
	 */
	long exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	/* ??? */
	unsigned long personality;
	unsigned did_exec:1;
	/*
	 * 进程标识符，通常顺序编号,新建进程是前一个进程的PID+1
	 * 上限为PID_MAX_DEFAULT-1(32位为32767),可通过/proc/sys/kernel/pid_max修改,通过pidmap_array来管理pid
	 * Linux线程组中的所有线程使用和该线程组领头线程相同的pid
	 *  
	 */
	pid_t pid;
	/*
	 * Linux线程组中的所有线程使用和该线程组领头线程相同的pid,也就是该组中第一个进程的pid
	 * 由getpid()返回当前进程的tgid
	 */
	pid_t tgid;
	/* 
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with 
	 * p->parent->pid)
	 */
	/*
	 * 指向创建了P的进程的描述符，如果P的父进程不存在，就指向init(进程1)
	 * 如：用于运行一个后台进程，且退出了shell,后台进程就会成为init的子进程
	 */
	struct task_struct *real_parent; /* real parent process (when being debugged) */
	/*
	 * 指向P的当前父进程（这种进程的子进程终止时，必须向父进程发信号）
	 * 它的值通常与real_parent一致，偶尔不同，如另一个进程发出监控P的ptrace()系统调用 
	 */
	struct task_struct *parent;	/* parent process */
	/*
	 * children/sibling forms the list of my children plus the
	 * tasks I'm ptracing.
	 */
	/*P的子进程链表头*/
	struct list_head children;	/* list of my children */
	/*P链入兄弟进程链表的连接件*/
	struct list_head sibling;	/* linkage in my parent's children list */
	/*P所在进程组的领头进程的描述符指针*/
	struct task_struct *group_leader;	/* threadgroup leader */

	/* PID/PID hash table linkage. */
	/*用于链入4个不同的pid_hash哈希表,参考pid定义注释*/
	struct pid pids[PIDTYPE_MAX];

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	/*
	 * 实时进程优先级（1~99）
	 * 用户可以通过sched_setparam()/sched_setscheduler改变进程的实时优先级
	 */
	unsigned long rt_priority;
	cputime_t utime, stime;
	unsigned long nvcsw, nivcsw; /* context switch counts */
	struct timespec start_time;
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

  	cputime_t it_prof_expires, it_virt_expires;
	unsigned long long it_sched_expires;
	struct list_head cpu_timers[3];

/* process credentials */
	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	struct group_info *group_info;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
	unsigned keep_capabilities:1;
	struct user_struct *user;
#ifdef CONFIG_KEYS
	struct key *thread_keyring;	/* keyring private to this thread */
	unsigned char jit_keyring;	/* default keyring to attach requested keys to */
#endif
	int oomkilladj; /* OOM kill score adjustment (bit shift). */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by flush_old_exec */
/* file system info */
	int link_count, total_link_count;
/* ipc stuff */
	struct sysv_sem sysvsem;
/* CPU-specific state of this task */
	/*用于保存硬件上下文*/
	struct thread_struct thread;
/* filesystem information */
	struct fs_struct *fs;
/* open file information */
	struct files_struct *files;
/* namespace */
	struct namespace *namespace;
/* signal handlers */
	struct signal_struct *signal;
	struct sighand_struct *sighand;

	sigset_t blocked, real_blocked;
	struct sigpending pending;

	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	int (*notifier)(void *priv);
	void *notifier_data;
	sigset_t *notifier_mask;
	
	void *security;
	struct audit_context *audit_context;
	seccomp_t seccomp;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings */
	spinlock_t alloc_lock;
/* Protection of proc_dentry: nesting proc_lock, dcache_lock, write_lock_irq(&tasklist_lock); */
	spinlock_t proc_lock;

/* journalling filesystem info */
	void *journal_info;

/* VM state */
	struct reclaim_state *reclaim_state;

	struct dentry *proc_dentry;
	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
/*
 * current io wait handle: wait queue entry to use for io waits
 * If this thread is processing aio, this points at the waitqueue
 * inside the currently handled kiocb. It may be NULL (i.e. default
 * to a stack based synchronous wait) if its doing sync IO.
 */
	wait_queue_t *io_wait;
/* i/o counters(bytes read/written, #syscalls */
	u64 rchar, wchar, syscr, syscw;
#if defined(CONFIG_BSD_PROCESS_ACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	clock_t acct_stimexpd;	/* clock_t-converted stime since last update */
#endif
#ifdef CONFIG_NUMA
  	struct mempolicy *mempolicy;
	short il_next;
#endif
#ifdef CONFIG_CPUSETS
	struct cpuset *cpuset;
	nodemask_t mems_allowed;
	int cpuset_mems_generation;
#endif
	atomic_t fs_excl;	/* holding fs exclusive resources */
};

static inline pid_t process_group(struct task_struct *tsk)
{
	return tsk->signal->pgrp;
}

/**
 * pid_alive - check that a task structure is not stale
 * @p: Task structure to be checked.
 *
 * Test if a process is not yet dead (at most zombie state)
 * If pid_alive fails, then pointers within the task structure
 * can be stale and must not be dereferenced.
 */
static inline int pid_alive(struct task_struct *p)
{
	return p->pids[PIDTYPE_PID].nr != 0;
}

extern void free_task(struct task_struct *tsk);
extern void __put_task_struct(struct task_struct *tsk);
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
/*如果对p的引用计数为0，则释放进程描述符*/
#define put_task_struct(tsk) \
do { if (atomic_dec_and_test(&(tsk)->usage)) __put_task_struct(tsk); } while(0)

/*
 * Per process flags
 */
#define PF_ALIGNWARN	0x00000001	/* Print alignment warning msgs */
					/* Not implemented yet, only for 486*/
#define PF_STARTING	0x00000002	/* being created */
#define PF_EXITING	0x00000004	/* getting shut down */
#define PF_DEAD		0x00000008	/* Dead */
#define PF_FORKNOEXEC	0x00000040	/* forked but didn't exec */
#define PF_SUPERPRIV	0x00000100	/* used super-user privileges */
#define PF_DUMPCORE	0x00000200	/* dumped core */
#define PF_SIGNALED	0x00000400	/* killed by a signal */
#define PF_MEMALLOC	0x00000800	/* Allocating memory */
#define PF_FLUSHER	0x00001000	/* responsible for disk writeback */
#define PF_USED_MATH	0x00002000	/* if unset the fpu must be initialized before use */
#define PF_FREEZE	0x00004000	/* this task is being frozen for suspend now */
#define PF_NOFREEZE	0x00008000	/* this thread should not be frozen */
#define PF_FROZEN	0x00010000	/* frozen for system suspend */
#define PF_FSTRANS	0x00020000	/* inside a filesystem transaction */
#define PF_KSWAPD	0x00040000	/* I am kswapd */
#define PF_SWAPOFF	0x00080000	/* I am in swapoff */
#define PF_LESS_THROTTLE 0x00100000	/* Throttle me less: I clean memory */
#define PF_SYNCWRITE	0x00200000	/* I am doing a sync write */
#define PF_BORROWED_MM	0x00400000	/* I am a kthread doing use_mm */
#define PF_RANDOMIZE	0x00800000	/* randomize virtual address space */

/*
 * Only the _current_ task can read/write to tsk->flags, but other
 * tasks can access tsk->flags in readonly mode for example
 * with tsk_used_math (like during threaded core dumping).
 * There is however an exception to this rule during ptrace
 * or during fork: the ptracer task is allowed to write to the
 * child->flags of its traced child (same goes for fork, the parent
 * can write to the child->flags), because we're guaranteed the
 * child is not running and in turn not changing child->flags
 * at the same time the parent does it.
 */
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define set_used_math() set_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
/* NOTE: this will return 0 or PF_USED_MATH, it will never return 1 */
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)

#ifdef CONFIG_SMP
extern int set_cpus_allowed(task_t *p, cpumask_t new_mask);
#else
static inline int set_cpus_allowed(task_t *p, cpumask_t new_mask)
{
	if (!cpu_isset(0, new_mask))
		return -EINVAL;
	return 0;
}
#endif

extern unsigned long long sched_clock(void);
extern unsigned long long current_sched_time(const task_t *current_task);

/* sched_exec is called by processes performing an exec */
#ifdef CONFIG_SMP
extern void sched_exec(void);
#else
#define sched_exec()   {}
#endif

#ifdef CONFIG_HOTPLUG_CPU
extern void idle_task_exit(void);
#else
static inline void idle_task_exit(void) {}
#endif

extern void sched_idle_next(void);
extern void set_user_nice(task_t *p, long nice);
extern int task_prio(const task_t *p);
extern int task_nice(const task_t *p);
extern int can_nice(const task_t *p, const int nice);
extern int task_curr(const task_t *p);
extern int idle_cpu(int cpu);
extern int sched_setscheduler(struct task_struct *, int, struct sched_param *);
extern task_t *idle_task(int cpu);
extern task_t *curr_task(int cpu);
extern void set_curr_task(int cpu, task_t *p);

void yield(void);

/*
 * The default (Linux) execution domain.
 */
extern struct exec_domain	default_exec_domain;

union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#ifndef __HAVE_ARCH_KSTACK_END
static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}
#endif

extern union thread_union init_thread_union;
extern struct task_struct init_task;

extern struct   mm_struct init_mm;

#define find_task_by_pid(nr)	find_task_by_pid_type(PIDTYPE_PID, nr)
extern struct task_struct *find_task_by_pid_type(int type, int pid);
extern void set_special_pids(pid_t session, pid_t pgrp);
extern void __set_special_pids(pid_t session, pid_t pgrp);

/* per-UID process charging. */
extern struct user_struct * alloc_uid(uid_t);
static inline struct user_struct *get_uid(struct user_struct *u)
{
	atomic_inc(&u->__count);
	return u;
}
extern void free_uid(struct user_struct *);
extern void switch_uid(struct user_struct *);

#include <asm/current.h>

extern void do_timer(struct pt_regs *);

extern int FASTCALL(wake_up_state(struct task_struct * tsk, unsigned int state));
extern int FASTCALL(wake_up_process(struct task_struct * tsk));
extern void FASTCALL(wake_up_new_task(struct task_struct * tsk,
						unsigned long clone_flags));
#ifdef CONFIG_SMP
 extern void kick_process(struct task_struct *tsk);
#else
 static inline void kick_process(struct task_struct *tsk) { }
#endif
extern void FASTCALL(sched_fork(task_t * p, int clone_flags));
extern void FASTCALL(sched_exit(task_t * p));

extern int in_group_p(gid_t);
extern int in_egroup_p(gid_t);

extern void proc_caches_init(void);
extern void flush_signals(struct task_struct *);
extern void flush_signal_handlers(struct task_struct *, int force_default);
extern int dequeue_signal(struct task_struct *tsk, sigset_t *mask, siginfo_t *info);

static inline int dequeue_signal_lock(struct task_struct *tsk, sigset_t *mask, siginfo_t *info)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&tsk->sighand->siglock, flags);
	ret = dequeue_signal(tsk, mask, info);
	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);

	return ret;
}	

extern void block_all_signals(int (*notifier)(void *priv), void *priv,
			      sigset_t *mask);
extern void unblock_all_signals(void);
extern void release_task(struct task_struct * p);
extern int send_sig_info(int, struct siginfo *, struct task_struct *);
extern int send_group_sig_info(int, struct siginfo *, struct task_struct *);
extern int force_sigsegv(int, struct task_struct *);
extern int force_sig_info(int, struct siginfo *, struct task_struct *);
extern int __kill_pg_info(int sig, struct siginfo *info, pid_t pgrp);
extern int kill_pg_info(int, struct siginfo *, pid_t);
extern int kill_proc_info(int, struct siginfo *, pid_t);
extern int kill_proc_info_as_uid(int, struct siginfo *, pid_t, uid_t, uid_t);
extern void do_notify_parent(struct task_struct *, int);
extern void force_sig(int, struct task_struct *);
extern void force_sig_specific(int, struct task_struct *);
extern int send_sig(int, struct task_struct *, int);
extern void zap_other_threads(struct task_struct *p);
extern int kill_pg(pid_t, int, int);
extern int kill_sl(pid_t, int, int);
extern int kill_proc(pid_t, int, int);
extern struct sigqueue *sigqueue_alloc(void);
extern void sigqueue_free(struct sigqueue *);
extern int send_sigqueue(int, struct sigqueue *,  struct task_struct *);
extern int send_group_sigqueue(int, struct sigqueue *,  struct task_struct *);
extern int do_sigaction(int, const struct k_sigaction *, struct k_sigaction *);
extern int do_sigaltstack(const stack_t __user *, stack_t __user *, unsigned long);

/* These can be the second arg to send_sig_info/send_group_sig_info.  */
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SEND_SIG_PRIV	((struct siginfo *) 1)
#define SEND_SIG_FORCED	((struct siginfo *) 2)

static inline int is_si_special(const struct siginfo *info)
{
	return info <= SEND_SIG_FORCED;
}

/* True if we are on the alternate signal stack.  */

static inline int on_sig_stack(unsigned long sp)
{
	return (sp - current->sas_ss_sp < current->sas_ss_size);
}

static inline int sas_ss_flags(unsigned long sp)
{
	return (current->sas_ss_size == 0 ? SS_DISABLE
		: on_sig_stack(sp) ? SS_ONSTACK : 0);
}


#ifdef CONFIG_SECURITY
/* code is in security.c */
extern int capable(int cap);
#else
static inline int capable(int cap)
{
	if (cap_raised(current->cap_effective, cap)) {
		current->flags |= PF_SUPERPRIV;
		return 1;
	}
	return 0;
}
#endif

/*
 * Routines for handling mm_structs
 */
extern struct mm_struct * mm_alloc(void);

/* mmdrop drops the mm and the page tables */
extern void FASTCALL(__mmdrop(struct mm_struct *));
static inline void mmdrop(struct mm_struct * mm)
{
	if (atomic_dec_and_test(&mm->mm_count))
		__mmdrop(mm);
}

/* mmput gets rid of the mappings and all user-space */
extern void mmput(struct mm_struct *);
/* Grab a reference to a task's mm, if it is not already going away */
extern struct mm_struct *get_task_mm(struct task_struct *task);
/* Remove the current tasks stale references to the old mm_struct */
extern void mm_release(struct task_struct *, struct mm_struct *);

extern int  copy_thread(int, unsigned long, unsigned long, unsigned long, struct task_struct *, struct pt_regs *);
extern void flush_thread(void);
extern void exit_thread(void);

extern void exit_files(struct task_struct *);
extern void exit_signal(struct task_struct *);
extern void __exit_signal(struct task_struct *);
extern void exit_sighand(struct task_struct *);
extern void __exit_sighand(struct task_struct *);
extern void exit_itimers(struct signal_struct *);

extern NORET_TYPE void do_group_exit(int);

extern void daemonize(const char *, ...);
extern int allow_signal(int);
extern int disallow_signal(int);
extern task_t *child_reaper;

extern int do_execve(char *, char __user * __user *, char __user * __user *, struct pt_regs *);
extern long do_fork(unsigned long, unsigned long, struct pt_regs *, unsigned long, int __user *, int __user *);
task_t *fork_idle(int);

extern void set_task_comm(struct task_struct *tsk, char *from);
extern void get_task_comm(char *to, struct task_struct *tsk);

#ifdef CONFIG_SMP
extern void wait_task_inactive(task_t * p);
#else
#define wait_task_inactive(p)	do { } while (0)
#endif

#define remove_parent(p)	list_del_init(&(p)->sibling)
#define add_parent(p, parent)	list_add_tail(&(p)->sibling,&(parent)->children)

#define REMOVE_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_del_init(&(p)->tasks);			\
	remove_parent(p);					\
	} while (0)

#define SET_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_add_tail(&(p)->tasks,&init_task.tasks);	\
	add_parent(p, (p)->parent);				\
	} while (0)

#define next_task(p)	list_entry((p)->tasks.next, struct task_struct, tasks)
#define prev_task(p)	list_entry((p)->tasks.prev, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

/*
 * Careful: do_each_thread/while_each_thread is a double loop so
 *          'break' will not work as expected - use goto instead.
 */
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do

#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

extern task_t * FASTCALL(next_thread(const task_t *p));

#define thread_group_leader(p)	(p->pid == p->tgid)

static inline int thread_group_empty(task_t *p)
{
	return list_empty(&p->pids[PIDTYPE_TGID].pid_list);
}

#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))

extern void unhash_process(struct task_struct *p);

/*
 * Protects ->fs, ->files, ->mm, ->ptrace, ->group_info, ->comm, keyring
 * subscriptions and synchronises with wait4().  Also used in procfs.  Also
 * pins the final release of task.io_context.  Also protects ->cpuset.
 *
 * Nests both inside and outside of read_lock(&tasklist_lock).
 * It must not be nested with write_lock_irq(&tasklist_lock),
 * neither inside nor outside.
 */
static inline void task_lock(struct task_struct *p)
{
	spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
	spin_unlock(&p->alloc_lock);
}

/* set thread flags in other task's structures
 * - see asm/thread_info.h for TIF_xxxx flags available
 */
static inline void set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	set_ti_thread_flag(tsk->thread_info,flag);
}

static inline void clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	clear_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_and_set_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_set_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_and_clear_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_and_clear_ti_thread_flag(tsk->thread_info,flag);
}

static inline int test_tsk_thread_flag(struct task_struct *tsk, int flag)
{
	return test_ti_thread_flag(tsk->thread_info,flag);
}

static inline void set_tsk_need_resched(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline void clear_tsk_need_resched(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk,TIF_NEED_RESCHED);
}

static inline int signal_pending(struct task_struct *p)
{
	return unlikely(test_tsk_thread_flag(p,TIF_SIGPENDING));
}
  
static inline int need_resched(void)
{
	return unlikely(test_thread_flag(TIF_NEED_RESCHED));
}

/*
 * cond_resched() and cond_resched_lock(): latency reduction via
 * explicit rescheduling in places that are safe. The return
 * value indicates whether a reschedule was done in fact.
 * cond_resched_lock() will drop the spinlock before scheduling,
 * cond_resched_softirq() will enable bhs before scheduling.
 */
extern int cond_resched(void);
extern int cond_resched_lock(spinlock_t * lock);
extern int cond_resched_softirq(void);

/*
 * Does a critical section need to be broken due to another
 * task waiting?:
 */
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
# define need_lockbreak(lock) ((lock)->break_lock)
#else
# define need_lockbreak(lock) 0
#endif

/*
 * Does a critical section need to be broken due to another
 * task waiting or preemption being signalled:
 */
static inline int lock_need_resched(spinlock_t *lock)
{
	if (need_lockbreak(lock) || need_resched())
		return 1;
	return 0;
}

/* Reevaluate whether the task has signals pending delivery.
   This is required every time the blocked sigset_t changes.
   callers must hold sighand->siglock.  */

extern FASTCALL(void recalc_sigpending_tsk(struct task_struct *t));
extern void recalc_sigpending(void);

extern void signal_wake_up(struct task_struct *t, int resume_stopped);

/*
 * Wrappers for p->thread_info->cpu access. No-op on UP.
 */
#ifdef CONFIG_SMP

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return p->thread_info->cpu;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
	p->thread_info->cpu = cpu;
}

#else

static inline unsigned int task_cpu(const struct task_struct *p)
{
	return 0;
}

static inline void set_task_cpu(struct task_struct *p, unsigned int cpu)
{
}

#endif /* CONFIG_SMP */

#ifdef HAVE_ARCH_PICK_MMAP_LAYOUT
extern void arch_pick_mmap_layout(struct mm_struct *mm);
#else
static inline void arch_pick_mmap_layout(struct mm_struct *mm)
{
	mm->mmap_base = TASK_UNMAPPED_BASE;
	mm->get_unmapped_area = arch_get_unmapped_area;
	mm->unmap_area = arch_unmap_area;
}
#endif

extern long sched_setaffinity(pid_t pid, cpumask_t new_mask);
extern long sched_getaffinity(pid_t pid, cpumask_t *mask);

#ifdef CONFIG_MAGIC_SYSRQ

extern void normalize_rt_tasks(void);

#endif

#ifdef CONFIG_PM
/*
 * Check if a process has been frozen
 */
static inline int frozen(struct task_struct *p)
{
	return p->flags & PF_FROZEN;
}

/*
 * Check if there is a request to freeze a process
 */
static inline int freezing(struct task_struct *p)
{
	return p->flags & PF_FREEZE;
}

/*
 * Request that a process be frozen
 * FIXME: SMP problem. We may not modify other process' flags!
 */
static inline void freeze(struct task_struct *p)
{
	p->flags |= PF_FREEZE;
}

/*
 * Wake up a frozen process
 */
static inline int thaw_process(struct task_struct *p)
{
	if (frozen(p)) {
		p->flags &= ~PF_FROZEN;
		wake_up_process(p);
		return 1;
	}
	return 0;
}

/*
 * freezing is complete, mark process as frozen
 */
static inline void frozen_process(struct task_struct *p)
{
	p->flags = (p->flags & ~PF_FREEZE) | PF_FROZEN;
}

extern void refrigerator(void);
extern int freeze_processes(void);
extern void thaw_processes(void);

static inline int try_to_freeze(void)
{
	if (freezing(current)) {
		refrigerator();
		return 1;
	} else
		return 0;
}
#else
static inline int frozen(struct task_struct *p) { return 0; }
static inline int freezing(struct task_struct *p) { return 0; }
static inline void freeze(struct task_struct *p) { BUG(); }
static inline int thaw_process(struct task_struct *p) { return 1; }
static inline void frozen_process(struct task_struct *p) { BUG(); }

static inline void refrigerator(void) {}
static inline int freeze_processes(void) { BUG(); return 0; }
static inline void thaw_processes(void) {}

static inline int try_to_freeze(void) { return 0; }

#endif /* CONFIG_PM */
#endif /* __KERNEL__ */

#endif
