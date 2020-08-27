#ifndef _ASM_KMAP_TYPES_H
#define _ASM_KMAP_TYPES_H

#include <linux/config.h>

#ifdef CONFIG_DEBUG_HIGHMEM
# define D(n) __KM_FENCE_##n ,
#else
# define D(n)
#endif
/*
 * 高端内存的任一页框都可以通过一个保留的页表项映射到内核地址空间
 * 每个CPU都有它自己的包含13个保留页表项的集合
 * 每一个枚举项即是一个固定映射线性地址的下标
 * 参考enum fixed_addresses
 *
 * ----+--------------+  <---------FIXADDR_TOP （0xfffff000UL)
 *  ^  |     ...      | 
 *  | -+--------------+  <----------------------------------------- FIXADDR_TOP-(FIX_KMAP_BEGIN  <<PAGE_SHIFT)
 *  | ^|              |  <----- FIXADDR_TOP-((FIX_KMAP_BEGIN+KM_BOUNCE_READ)      <<PAGE_SHIFT)
 *  | ||              |  <----- FIXADDR_TOP-((FIX_KMAP_BEGIN+KM_SKB_SUNRPC_DATA)  <<PAGE_SHIFT)
 * 固临|              |
 * 定时|              |  ......
 * 映映|              |
 * 射射|              |
 *  | ||              |
 *  | v|              |  <----- FIXADDR_TOP-((FIX_KMAP_BEGIN+KM_SOFTIRQ1)            <<PAGE_SHIFT)
 *  | -+--------------+  <----------------------------------------- FIXADDR_TOP-(FIX_KMAP_END  <<PAGE_SHIFT)
 *  v  |     ...      |
 * ----+--------------+  <---------FIXADDR_BOOT_START
 *     |              |  
 *     |   永久映射   |
 *     |              |
 *     +--------------+  <---------PKMAP_BASE
 *     |      8kb     |
 *     +--------------+  <---------VMALLOC_END
 *     |  vmalloc区   |
 *     +--------------+
 *     |      4kb     |
 *     +--------------+
 *     |  vmalloc区   |
 *     +--------------+  <---------VMALLOC_START
 *     |      8MB     |
 *     +--------------+  <---------high memory
 *     | 物理内存映射 | 
 *     +--------------+  <---------PAGE_OFFSET
 *
 *
 * NOTE: FIXADDR_TOP~FIXADDR_BOOT_START为固定映射区
 */
enum km_type {
D(0)	KM_BOUNCE_READ,
D(1)	KM_SKB_SUNRPC_DATA,
D(2)	KM_SKB_DATA_SOFTIRQ,
D(3)	KM_USER0,
D(4)	KM_USER1,
D(5)	KM_BIO_SRC_IRQ,
D(6)	KM_BIO_DST_IRQ,
D(7)	KM_PTE0,
D(8)	KM_PTE1,
D(9)	KM_IRQ0,
D(10)	KM_IRQ1,
D(11)	KM_SOFTIRQ0,
D(12)	KM_SOFTIRQ1,
D(13)	KM_TYPE_NR
};

#undef D

#endif
