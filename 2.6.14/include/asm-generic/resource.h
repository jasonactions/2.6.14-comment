#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

/*
 * Resource limit IDs
 *
 * ( Compatibility detail: there are architectures that have
 *   a different rlimit ID order in the 5-9 range and want
 *   to keep that order for binary compatibility. The reasons
 *   are historic and all new rlimits are identical across all
 *   arches. If an arch has such special order for some rlimits
 *   then it defines them prior including asm-generic/resource.h. )
 */
/*如下是进程资源限制的ID，相关限制值保存在task_struct->signal->rlim数组*/

/*进程使用CPU的最长时间*/
#define RLIMIT_CPU		0	/* CPU time in ms */
/*文件大小的最大值（字节）*/
#define RLIMIT_FSIZE		1	/* Maximum filesize */
/*堆大小的最大值（字节）*/
#define RLIMIT_DATA		2	/* max data size */
/*栈大小的最大值（字节）*/
#define RLIMIT_STACK		3	/* max stack size */
/*内存信息转储文件的大小（字节）*/
#define RLIMIT_CORE		4	/* max core file size */

#ifndef RLIMIT_RSS
/*进程拥有的页框最大数*/
# define RLIMIT_RSS		5	/* max resident set size */
#endif

#ifndef RLIMIT_NPROC
/*用户能拥有的进程最大数*/
# define RLIMIT_NPROC		6	/* max number of processes */
#endif

#ifndef RLIMIT_NOFILE
/*进程能打开文件的最大数*/
# define RLIMIT_NOFILE		7	/* max number of open files */
#endif

#ifndef RLIMIT_MEMLOCK
/*非交换内存的最大值（字节）*/
# define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#endif

#ifndef RLIMIT_AS
/*进程地址空间的最大数*/
# define RLIMIT_AS		9	/* address space limit */
#endif

/*文件锁的最大值???*/
#define RLIMIT_LOCKS		10	/* maximum file locks held */
/*进程挂起信号的最大数*/
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
/*POSIX消息队列的最大数*/
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE		13	/* max nice prio allowed to raise to
					   0-39 for nice level 19 .. -20 */
/*最大实时优先级*/
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */

#define RLIM_NLIMITS		15

/*
 * SuS says limits have to be unsigned.
 * Which makes a ton more sense anyway.
 *
 * Some architectures override this (for compatibility reasons):
 */
#ifndef RLIM_INFINITY
# define RLIM_INFINITY		(~0UL)
#endif

/*
 * RLIMIT_STACK default maximum - some architectures override it:
 */
#ifndef _STK_LIM_MAX
# define _STK_LIM_MAX		RLIM_INFINITY
#endif

#ifdef __KERNEL__

/*
 * boot-time rlimit defaults for the init task:
 */
#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_DATA]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {       _STK_LIM,   _STK_LIM_MAX },	\
	[RLIMIT_CORE]		= {              0,  RLIM_INFINITY },	\
	[RLIMIT_RSS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {              0,              0 },	\
	[RLIMIT_NOFILE]		= {       INR_OPEN,       INR_OPEN },	\
	[RLIMIT_MEMLOCK]	= {    MLOCK_LIMIT,    MLOCK_LIMIT },	\
	[RLIMIT_AS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { 		0,	       0 },	\
	[RLIMIT_MSGQUEUE]	= {   MQ_BYTES_MAX,   MQ_BYTES_MAX },	\
	[RLIMIT_NICE]		= { 0, 0 },				\
	[RLIMIT_RTPRIO]		= { 0, 0 },				\
}

#endif	/* __KERNEL__ */

#endif
