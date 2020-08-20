#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>
#include <linux/config.h>

struct vm_area_struct;

/*
 * GFP bitmasks..
 */
/* Zone modifiers in GFP_ZONEMASK (see linux/mmzone.h - low two bits) */
/*所请求的页框必须位于ZONE_DMA，等价于GFP_DMA*/
#define __GFP_DMA	((__force gfp_t)0x01u)
/*请求的页框必须位于ZONE_HIGHMEM，等价于GFP_HIGHMEM*/
#define __GFP_HIGHMEM	((__force gfp_t)0x02u)

/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 */
/*允许内核对等待空闲页框的当前进程进行阻塞*/
#define __GFP_WAIT	((__force gfp_t)0x10u)	/* Can wait and reschedule? */
/*允许内核访问保留的页框池*/
#define __GFP_HIGH	((__force gfp_t)0x20u)	/* Should access emergency pools? */
/*允许内核在低端内存页上执行I/O传输以释放页框*/
#define __GFP_IO	((__force gfp_t)0x40u)	/* Can start physical IO? */
/*如果清0，则不允许内核执行依赖于文件按系统的操作*/
#define __GFP_FS	((__force gfp_t)0x80u)	/* Can call down to low-level FS? */
/*所请求的页框可能为冷的,硬件高速缓存中无对应数据*/
#define __GFP_COLD	((__force gfp_t)0x100u)	/* Cache-cold page required */
/*一次内存分配失败不会产生警告信息*/
#define __GFP_NOWARN	((__force gfp_t)0x200u)	/* Suppress page allocation failure warning */
/*内核重试内存分配直到成功*/
#define __GFP_REPEAT	((__force gfp_t)0x400u)	/* Retry the allocation.  Might fail */
/*同__GFP_REPEAT*/
#define __GFP_NOFAIL	((__force gfp_t)0x800u)	/* Retry for ever.  Cannot fail */
/*一次分配失败后不再重试*/
#define __GFP_NORETRY	((__force gfp_t)0x1000u)/* Do not retry.  Might fail */
/*slab分配器不允许增大slab高速缓存???*/
#define __GFP_NO_GROW	((__force gfp_t)0x2000u)/* Slab internal usage */
/*属于扩展页的页框???*/
#define __GFP_COMP	((__force gfp_t)0x4000u)/* Add compound page metadata */
/*返回的页框填充0*/
#define __GFP_ZERO	((__force gfp_t)0x8000u)/* Return zeroed page on success */
/*不要使用保留内存*/
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) /* Don't use emergency reserves */
/*分配页框时不允许页面回收*/
#define __GFP_NORECLAIM  ((__force gfp_t)0x20000u) /* No realy zone reclaim during allocation */
/*只能在当前进程可运行的cpu关联的内存节点上分配内存，如果进程可在所有cpu上运行，该标志无意义*/
#define __GFP_HARDWALL   ((__force gfp_t)0x40000u) /* Enforce hardwall cpuset memory allocs */
#define __GFP_BITS_SHIFT 20	/* Room for 20 __GFP_FOO bits */
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/* if you forget to add the bitmask here kernel will crash, period */
#define GFP_LEVEL_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS| \
			__GFP_COLD|__GFP_NOWARN|__GFP_REPEAT| \
			__GFP_NOFAIL|__GFP_NORETRY|__GFP_NO_GROW|__GFP_COMP| \
			__GFP_NOMEMALLOC|__GFP_NORECLAIM|__GFP_HARDWALL)

/* 表示申请内存非常紧急，不能睡眠，不能有IO和VFS操作 */
#define GFP_ATOMIC	(__GFP_HIGH)
/* 表示可以睡眠，不能有IO操作*/
#define GFP_NOIO	(__GFP_WAIT)
/* 表示可以睡眠，可以有IO操作，不能有VFS操作 */
#define GFP_NOFS	(__GFP_WAIT | __GFP_IO)
/* 表示可以睡眠，可以有IO操作和VFS操作 */
#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)
/* 可以睡眠，可以有IO和VFS操作，只能从进程可运行的node上分配内存 */
#define GFP_USER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
/* 优先从高端zone中分配内存 */
#define GFP_HIGHUSER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
			 __GFP_HIGHMEM)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA		__GFP_DMA

#define gfp_zone(mask) ((__force int)((mask) & (__force gfp_t)GFP_ZONEMASK))

/*
 * There is only one page-allocator function, and two main namespaces to
 * it. The alloc_page*() variants return 'struct page *' and as such
 * can allocate highmem pages, the *get*page*() variants return
 * virtual kernel addresses to the allocated page(s).
 */

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAXNODES*MAX_NR_ZONES zones.
 *
 * For the normal case of non-DISCONTIGMEM systems the NODE_DATA() gets
 * optimized to &contig_page_data at compile-time.
 */

#ifndef HAVE_ARCH_FREE_PAGE
static inline void arch_free_page(struct page *page, int order) { }
#endif

extern struct page *
FASTCALL(__alloc_pages(gfp_t, unsigned int, struct zonelist *));

static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	return __alloc_pages(gfp_mask, order,
		NODE_DATA(nid)->node_zonelists + gfp_zone(gfp_mask));
}

#ifdef CONFIG_NUMA
extern struct page *alloc_pages_current(gfp_t gfp_mask, unsigned order);

/*
 * 返回第一个被分配页框的页描述符的线性地址，可用于分配高端内存
 * 因为页描述符在初始化分配在低端内存中，且不会改变
 */
static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	return alloc_pages_current(gfp_mask, order);
}
extern struct page *alloc_page_vma(gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr);
#else
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#endif
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

extern unsigned long FASTCALL(__get_free_pages(gfp_t gfp_mask, unsigned int order));
extern unsigned long FASTCALL(get_zeroed_page(gfp_t gfp_mask));

/*只能用来分配低端内存，因为高端内存的线性地址不存在*/
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)

#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))

extern void FASTCALL(__free_pages(struct page *page, unsigned int order));
extern void FASTCALL(free_pages(unsigned long addr, unsigned int order));
extern void FASTCALL(free_hot_page(struct page *page));
extern void FASTCALL(free_cold_page(struct page *page));

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr),0)

void page_alloc_init(void);
#ifdef CONFIG_NUMA
void drain_remote_pages(void);
#else
static inline void drain_remote_pages(void) { };
#endif

#endif /* __LINUX_GFP_H */
