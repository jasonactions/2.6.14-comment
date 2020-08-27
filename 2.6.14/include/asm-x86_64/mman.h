#ifndef __X8664_MMAN_H__
#define __X8664_MMAN_H__

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_SEM	0x8
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

/*指定线性区中的页可以被几个进程共享*/
#define MAP_SHARED	0x01		/* Share changes */
/*指定线性区中的页只能被当前进程独享*/
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
/*区间的起始地址必须由addr指定*/
#define MAP_FIXED	0x10		/* Interpret addr exactly */
/*没有文件与这个线性区相关联*/
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_32BIT	0x40		/* only give out 32bit addresses */

#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */
/*函数不必预先检查空闲页框的数目*/
#define MAP_NORESERVE	0x4000		/* don't check for reservations */
/*函数应该为线性区建立的映射提前分配需要的页框，其只对映射文件线性区和共享线性区有意义*/
#define MAP_POPULATE	0x8000		/* populate (prefault) pagetables */
/*MAP_POPULATE置位才有意义*/
#define MAP_NONBLOCK	0x10000		/* do not block on IO */

#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */

#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */

#define MADV_NORMAL	0x0		/* default page-in behavior */
#define MADV_RANDOM	0x1		/* page-in minimum required */
#define MADV_SEQUENTIAL	0x2		/* read-ahead aggressively */
#define MADV_WILLNEED	0x3		/* pre-fault pages */
#define MADV_DONTNEED	0x4		/* discard these pages */

/* compatibility flags */
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FILE	0

#endif
