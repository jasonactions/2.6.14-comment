#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/sched.h>
#include <linux/errno.h>

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mmzone.h>
#include <linux/rbtree.h>
#include <linux/prio_tree.h>
#include <linux/fs.h>

struct mempolicy;
struct anon_vma;

#ifndef CONFIG_DISCONTIGMEM          /* Don't use mapnrs, do it properly */
extern unsigned long max_mapnr;
#endif

extern unsigned long num_physpages;
extern void * high_memory;
extern unsigned long vmalloc_earlyreserve;
extern int page_cluster;

#ifdef CONFIG_SYSCTL
extern int sysctl_legacy_va_layout;
#else
#define sysctl_legacy_va_layout 0
#endif

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/atomic.h>

#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))

/*
 * Linux kernel virtual memory manager primitives.
 * The idea being to have a "virtual" mm in the same way
 * we have a virtual fs - giving a cleaner interface to the
 * mm details, and allowing different kinds of memory mappings
 * (from shared memory to executable loading to arbitrary
 * mmap() functions).
 */

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/* mfile_start     vm_start address       vm_end    mfile_end
 *    +---------------+--------+-------------+--------+
 *    |               |        |             |        |    
 *    +-----------------------------------------------+
 *    |<--vm_pgoff-->|
 */
/*
 * 线性区描述符,线性区不同重叠，通过两种方法存储：
 * 1.通过链表，进程所有线性区以内存地址升序链接在一起,链表头位于mm_struct->mmap
 * 2.通过红黑树存放
 */
/*
 * 经典进程地址空间布局：
 *
 *          +--------------------+
 *          |     内核空间       |---------------------->用户代码不可见区域
 *          +--------------------+----->0xc000 0000
 *          |     栈随机偏移     |
 *          +--------------------+
 *          |   Stack(用户栈)    |
 *          |        |           |---------------------->ESP指向栈顶
 *          |        V           |
 *          +                    +---------------------->空闲区域
 *          |        ^           |
 *          |        |           |
 *          |    mmap映射区      |
 *          +--------------------+----->0x4000 0000
 *          |        ^           |
 *          |        |           |---------------------->通过brk/sbrk系统调用扩大堆，向上增长。
 *          |       Heap         |
 *          +--------------------+
 *          | .data、.bss(读写段)|---------------------->从可执行文件中加载
 *          +--------------------+
 *          |.init .text .rodata |---------------------->从可执行文件中加载
 *          |      (只读段)      |
 *          +--------------------+----->0x0804 8000
 *          |      保留区域      |
 *          +--------------------+
 *
 *  灵活进程空间新布局：
 *
 *          +--------------------+
 *          |     内核空间       |---------------------->用户代码不可见区域
 *          +--------------------+----->0xc000 0000
 *          |     栈随机偏移     |
 *          +--------------------+
 *          |   Stack(用户栈)    |
 *          |        |           |---------------------->ESP指向栈顶
 *          |        V           |
 *          +--------------------+
 *          |     mmap映射区     |
 *          |        |           |
 *          |        V           |
 *          |                    |
 *          +                    +
 *          |        ^           |
 *          |        |           |---------------------->通过brk/sbrk系统调用扩大堆，向上增长。
 *          |       Heap         |
 *          +--------------------+
 *          | .data、.bss(读写段)|---------------------->从可执行文件中加载
 *          +--------------------+
 *          |.init .text .rodata |---------------------->从可执行文件中加载
 *          |      (只读段)      |
 *          +--------------------+----->0x0804 8000
 *          |      保留区域      |
 *          +--------------------+ 
 */
struct vm_area_struct {
	/*指向线性区所在的内存描述符*/
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	/*
	 * vm_start博阿含区间的第一个线性地址；vm_end包含区间之外的第一个线性地址
	 * vm_end-vm_start表示区间长度
	 * 对于内存映射vm_start和vm_end表示映射文件的长度,也是线性区的大小
	 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/*进程链表的下一个线性区*/
	struct vm_area_struct *vm_next;

	/*线性区中页框的访问许可权,页表标志的初值*/
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/*线性区的标志*/
	unsigned long vm_flags;		/* Flags, listed below. */

	/*用于红黑树的数据*/
	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/*链接到反映射所使用的数据结构*/
	union {
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.  A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	/*链入匿名线性区链表的链接件*/
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	/*反向映射*/
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	/*指向线性区的方法*/
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/*
	 * 对文件页，它是映射文件偏移量，内存映射文件的第一个映射单元的位置,以页大小为单位
	 * 对匿名页，它等于0或vm_start/PAGE_SIZE
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/*指向所映射文件的文件对象*/
	struct file * vm_file;		/* File we map to (can be NULL). */
	/*指向内存区私有数据,如：在非线性映射时存放当前扫描的当前指针*/
	void * vm_private_data;		/* was vm_pte (shared mem) */
	/*释放非线性文件内存映射中的一个线性地址区间时使用*/
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

/*
 * This struct defines the per-mm list of VMAs for uClinux. If CONFIG_MMU is
 * disabled, then there's a single shared list of VMAs maintained by the
 * system, and mm's subscribe to these individually
 */
struct vm_list_struct {
	struct vm_list_struct	*next;
	struct vm_area_struct	*vma;
};

#ifndef CONFIG_MMU
extern struct rb_root nommu_vma_tree;
extern struct rw_semaphore nommu_vma_sem;

extern unsigned int kobjsize(const void *objp);
#endif

/*
 * vm_flags..
 */
/*页可读*/
#define VM_READ		0x00000001	/* currently active flags */
/*页可写*/
#define VM_WRITE	0x00000002
/*页可执行*/
#define VM_EXEC		0x00000004
/*页可以被几个进程共享*/
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
/*可以设置VM_READ标志*/
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
/*可以设置VM_WRITE标志*/ 
#define VM_MAYWRITE	0x00000020
/*可以设置VM_EXEC标志*/ 
#define VM_MAYEXEC	0x00000040
/*可以设置VM_SHARE标志*/ 
#define VM_MAYSHARE	0x00000080

/*线性区可以向低地址扩展*/
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
/*线性区可以向高地址扩展*/
#define VM_GROWSUP	0x00000200
/*线性区用于IPC共享内存*/
#define VM_SHM		0x00000400	/* shared memory area, don't swap out */
/*线性区映射一个不能打开用于写的文件*/
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

/*线性区映射一个可执行文件*/
#define VM_EXECUTABLE	0x00001000
/*线性区中的页锁定，不能换出*/
#define VM_LOCKED	0x00002000
/*线性区用于映射设备的IO地址空间*/
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */


/*应用程序顺序访问页*/			/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
/*应用程序以真正的随机顺序访问页*/
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

/*当创建一个新进程时不拷贝线性区*/
#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
/*通过mremap()系统调用禁止线性区扩展*/
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
/*线性区是特殊的（如映射到某个设备的IO地址空间），不能被交换出去*/
#define VM_RESERVED	0x00080000	/* Pages managed in a special way */
/*创建IPC共享线性区时检查是否有足够的空闲内存用于映射*/
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
/*通过扩展分页机制处理线性区中的页???*/
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
/*线性区实现非线性文件映射???*/
#define VM_NONLINEAR	0x00800000	/* Is non-linear (remap_file_pages) */
#define VM_MAPPED_COPY	0x01000000	/* T if mapped copy of data (nommu mmap) */

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK_FLAGS	(VM_GROWSUP | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#else
#define VM_STACK_FLAGS	(VM_GROWSDOWN | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#endif

#define VM_READHINTMASK			(VM_SEQ_READ | VM_RAND_READ)
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_SequentialReadHint(v)	((v)->vm_flags & VM_SEQ_READ)
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)

/*
 * mapping from the currently active vm_flags protection bits (the
 * low four bits) to a page protection mask..
 */
extern pgprot_t protection_map[16];


/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs. 
 */
/*线性区函数集*/
struct vm_operations_struct {
	/*把线性区增加到进程所拥有的线性区集合时使用*/
	void (*open)(struct vm_area_struct * area);
	/*当从进程所拥有的线性区集合删除线性区时使用*/
	void (*close)(struct vm_area_struct * area);
	/*当进程试图访问RAM不存在的页，但该页的线性地址属于线性区时，由缺页异常处理程序调用*/
	struct page * (*nopage)(struct vm_area_struct * area, unsigned long address, int *type);
	/*设置线性区的线性地址所对应的页表项时调用，主要用于非线性文件内存映射???*/
	int (*populate)(struct vm_area_struct * area, unsigned long address, unsigned long len, pgprot_t prot, unsigned long pgoff, int nonblock);
#ifdef CONFIG_NUMA
	int (*set_policy)(struct vm_area_struct *vma, struct mempolicy *new);
	struct mempolicy *(*get_policy)(struct vm_area_struct *vma,
					unsigned long addr);
#endif
};

struct mmu_gather;
struct inode;

#ifdef ARCH_HAS_ATOMIC_UNSIGNED
typedef unsigned page_flags_t;
#else
typedef unsigned long page_flags_t;
#endif

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page.
 */
/*
 * ==页框回收处理的页框类型==
 *
 * 1.不可回收页: 不允许也无需回收
 *   |--空闲页（包含在伙伴系统中）
 *   |--保留页
 *   |--内核动态分配页
 *   |--进程内核态堆栈页
 *   |--临时锁定页（PG_locked标志置位）
 *   |--内存锁定页（在线性区中且VM_LOCKED标志置位）
 * 2.可交换页：将页的内容保存在交换区
 *   |--用户态地址空间的匿名页
 *   |--tmpfs文件系统的映射页（如IPC共享内存的页）
 * 3.可同步页：必要时，与磁盘映像同步这些页
 *   |--用户态地址空间的映射页
 *   |--存有磁盘文件数据且在页高速缓存中的页
 *   |--块设备缓冲区页
 *   |--某些磁盘高速缓存的页（如索引节点高速缓存）
 * 4.可丢弃页：无需操作
 *   |--内存高速缓存未使用的页（如slab分配器高速缓存）
 *   |--目录项高速缓存的未使用页
 *
 * ==页框回收算法的基本原则==
 * 1.首先释放无害页：没有任何进程使用的磁盘高速缓存的页
 * 2.将用户态进程的所有页定为可回收页：除了锁定页
 * 3.同时取消引用一个共享页的所有页表项的映射即可回收该共享页框
 * 4.只回收未用页：长时间没有被访问的页
 *
 * ==页框回收算法执行的基本情形==
 * 1.内存紧缺回收：内存发现内存紧缺,grow_buffers()/alloc_page_buffers()/__alloc_pages()时激活
 * 2.睡眠回收：suspend-to-disk时
 * 3.周期回收：周期性激活内核线程执行内存回收算法，kswapd/events内核线程激活
 */
/*页框描述符，所有页描述符保存在mem_map中*/
struct page {
	/*
	 * 一组标志PG_xyz，PageXyz返回标志的值，SetPageXyz和ClearPageXyz分别设置和清除相应的位
	 *  对页框所在管理区进行编号
	 *  flags高位用来编码特定内存节点和管理区号
	 *
	 *  注：与page相关的标志有三种：1.页表项中存放的；2.此处存放的标志;3.vm_area_strut->vm_flags
	 */
	page_flags_t flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/* 页的引用计数，-1:表示页框空闲; >=0: 说明分配给一个或多个进程或存放内核数据结构，
	 * page_count返回_count加1，表示页使用者数目*/
	atomic_t _count;		/* Usage count, see below. */
	/*
	 * 引用页框中的页表项数目，-1：没有页表项引用此页框；0:非共享；>0: 共享的
	 * page_mapcount()返回_mapcount+1
	 */
	atomic_t _mapcount;		/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
	union {
		/*
		 * 可用于正在使用页的内核成分
		 * 1.对于page cache(PG_private置位)
		 *   private指向第一个buffer_head
		 * 2.如果页是空闲页框块
		 *   页框块的第一个page，则由buddy使用保存page所属页框块的order
		 *   它可以用于相邻页框块是否可以合并为2^(order+1)大小的页框快
		 * 3.对于交换高速缓存（PG_swapcache置位）
		 *   存放与页有关的换出页标识符（交换区索引和页槽索引，type | offset）
		 */
		unsigned long private;	/* Mapping-private opaque data:
					 * usually used for buffer_heads
					 * if PagePrivate set; used for
					 * swp_entry_t if PageSwapCache
					 * When page is free, this indicates
					 * order in the buddy system.
					 */
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
		spinlock_t ptl;
#endif
	} u;
	/*
	 * 用于判断页是映射页还是匿名页
	 * (1)mapping为空：页属于交换高速缓存
	 * (2)mapping非空，且最低位是1，表示该页为匿名页，mapping保存vma->anon_vma的地址
	 * (3)mapping非空，且最低位为0，表示该页为映射页，mapping指向对应文件的address_space对象
	 * 注：.address_space对象地址在RAM中按4字节对齐，所以最低位可以使用
	 *     .PageAnon以页描述符为参数，返回mapping的最低位是否置1
	 *     .anon_vma为匿名页所在线性区VMA的链表头
	 */
	struct address_space *mapping;	/* If low bit clear, points to
					 * inode address_space, or NULL.
					 * If page mapped as anonymous
					 * memory, low bit is set, and
					 * it points to anon_vma object:
					 * see PAGE_MAPPING_ANON below.
					 */
	/*
	 * 存放文件的页索引或存放一个换出页标识符
	 * 对于匿名页，存放线性区内的页索引或页的线性地址/PAGE_SIZE
	 * 对于文件页，存放被映射文件内的页偏移量
	 */
	pgoff_t index;			/* Our offset within mapping. */
	/*
	 * 当页空闲时lru链入到free_area->free_list链表，不空闲时链接到lru链表的链接件
	 * 如果page是slab的一个页框，则lru->next和lru->prev分别存放高速缓存描述符和slab描述符
	 */
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

#define page_private(page)		((page)->u.private)
#define set_page_private(page, v)	((page)->u.private = (v))

/*
 * FIXME: take this include out, include page-flags.h in
 * files which need it (119 of them)
 */
#include <linux/page-flags.h>

/*
 * Methods to modify the page usage count.
 *
 * What counts for a page usage:
 * - cache mapping   (page->mapping)
 * - private data    (page->private)
 * - page mapped in a task's page tables, each mapping
 *   is counted separately
 *
 * Also, many kernel routines increase the page count before a critical
 * routine so they can be sure the page doesn't go away from under them.
 *
 * Since 2.6.6 (approx), a free page has ->_count = -1.  This is so that we
 * can use atomic_add_negative(-1, page->_count) to detect when the page
 * becomes free and so that we can also use atomic_inc_and_test to atomically
 * detect when we just tried to grab a ref on a page which some other CPU has
 * already deemed to be freeable.
 *
 * NO code should make assumptions about this internal detail!  Use the provided
 * macros which retain the old rules: page_count(page) == 0 is a free page.
 */

/*
 * Drop a ref, return true if the logical refcount fell to zero (the page has
 * no users)
 */
#define put_page_testzero(p)				\
	({						\
		BUG_ON(page_count(p) == 0);		\
		atomic_add_negative(-1, &(p)->_count);	\
	})

/*
 * Grab a ref, return true if the page previously had a logical refcount of
 * zero.  ie: returns true if we just grabbed an already-deemed-to-be-free page
 */
#define get_page_testone(p)	atomic_inc_and_test(&(p)->_count)

#define set_page_count(p,v) 	atomic_set(&(p)->_count, v - 1)
#define __put_page(p)		atomic_dec(&(p)->_count)

extern void FASTCALL(__page_cache_release(struct page *));

#ifdef CONFIG_HUGETLB_PAGE

static inline int page_count(struct page *page)
{
	if (PageCompound(page))
		page = (struct page *)page_private(page);
	return atomic_read(&page->_count) + 1;
}

static inline void get_page(struct page *page)
{
	if (unlikely(PageCompound(page)))
		page = (struct page *)page_private(page);
	atomic_inc(&page->_count);
}

void put_page(struct page *page);

#else		/* CONFIG_HUGETLB_PAGE */

#define page_count(p)		(atomic_read(&(p)->_count) + 1)

static inline void get_page(struct page *page)
{
	atomic_inc(&page->_count);
}

static inline void put_page(struct page *page)
{
	/*如果page引用计数为0*/
	if (put_page_testzero(page))
		/*释放page*/
		__page_cache_release(page);
}

#endif		/* CONFIG_HUGETLB_PAGE */

/*
 * Multiple processes may "see" the same page. E.g. for untouched
 * mappings of /dev/null, all processes see the same page full of
 * zeroes, and text pages of executables and shared libraries have
 * only one copy in memory, at most, normally.
 *
 * For the non-reserved pages, page_count(page) denotes a reference count.
 *   page_count() == 0 means the page is free. page->lru is then used for
 *   freelist management in the buddy allocator.
 *   page_count() == 1 means the page is used for exactly one purpose
 *   (e.g. a private data page of one process).
 *
 * A page may be used for kmalloc() or anyone else who does a
 * __get_free_page(). In this case the page_count() is at least 1, and
 * all other fields are unused but should be 0 or NULL. The
 * management of this page is the responsibility of the one who uses
 * it.
 *
 * The other pages (we may call them "process pages") are completely
 * managed by the Linux memory manager: I/O, buffers, swapping etc.
 * The following discussion applies only to them.
 *
 * A page may belong to an inode's memory mapping. In this case,
 * page->mapping is the pointer to the inode, and page->index is the
 * file offset of the page, in units of PAGE_CACHE_SIZE.
 *
 * A page contains an opaque `private' member, which belongs to the
 * page's address_space.  Usually, this is the address of a circular
 * list of the page's disk buffers.
 *
 * For pages belonging to inodes, the page_count() is the number of
 * attaches, plus 1 if `private' contains something, plus one for
 * the page cache itself.
 *
 * Instead of keeping dirty/clean pages in per address-space lists, we instead
 * now tag pages as dirty/under writeback in the radix tree.
 *
 * There is also a per-mapping radix tree mapping index to the page
 * in memory if present. The tree is rooted at mapping->root.  
 *
 * All process pages can do I/O:
 * - inode pages may need to be read from disk,
 * - inode pages which have been modified and are MAP_SHARED may need
 *   to be written to disk,
 * - private pages which have been modified may need to be swapped out
 *   to swap space and (later) to be read back into memory.
 */

/*
 * The zone field is never updated after free_area_init_core()
 * sets it, so none of the operations on it need to be atomic.
 */


/*
 * page->flags layout:
 *
 * There are three possibilities for how page->flags get
 * laid out.  The first is for the normal case, without
 * sparsemem.  The second is for sparsemem when there is
 * plenty of space for node and section.  The last is when
 * we have run out of space and have to fall back to an
 * alternate (slower) way of determining the node.
 *
 *        No sparsemem: |       NODE     | ZONE | ... | FLAGS |
 * with space for node: | SECTION | NODE | ZONE | ... | FLAGS |
 *   no space for node: | SECTION |     ZONE    | ... | FLAGS |
 */
#ifdef CONFIG_SPARSEMEM
#define SECTIONS_WIDTH		SECTIONS_SHIFT
#else
#define SECTIONS_WIDTH		0
#endif

#define ZONES_WIDTH		ZONES_SHIFT

#if SECTIONS_WIDTH+ZONES_WIDTH+NODES_SHIFT <= FLAGS_RESERVED
#define NODES_WIDTH		NODES_SHIFT
#else
#define NODES_WIDTH		0
#endif

/* Page flags: | [SECTION] | [NODE] | ZONE | ... | FLAGS | */
#define SECTIONS_PGOFF		((sizeof(page_flags_t)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF		(SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF		(NODES_PGOFF - ZONES_WIDTH)

/*
 * We are going to use the flags for the page to node mapping if its in
 * there.  This includes the case where there is no node, so it is implicit.
 */
#define FLAGS_HAS_NODE		(NODES_WIDTH > 0 || NODES_SHIFT == 0)

#ifndef PFN_SECTION_SHIFT
#define PFN_SECTION_SHIFT 0
#endif

/*
 * Define the bit shifts to access each section.  For non-existant
 * sections we define the shift as 0; that plus a 0 mask ensures
 * the compiler will optimise away reference to them.
 */
#define SECTIONS_PGSHIFT	(SECTIONS_PGOFF * (SECTIONS_WIDTH != 0))
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT		(ZONES_PGOFF * (ZONES_WIDTH != 0))

/* NODE:ZONE or SECTION:ZONE is used to lookup the zone from a page. */
#if FLAGS_HAS_NODE
#define ZONETABLE_SHIFT		(NODES_SHIFT + ZONES_SHIFT)
#else
#define ZONETABLE_SHIFT		(SECTIONS_SHIFT + ZONES_SHIFT)
#endif
#define ZONETABLE_PGSHIFT	ZONES_PGSHIFT

#if SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > FLAGS_RESERVED
#error SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > FLAGS_RESERVED
#endif

#define ZONES_MASK		((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK		((1UL << NODES_WIDTH) - 1)
#define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
#define ZONETABLE_MASK		((1UL << ZONETABLE_SHIFT) - 1)

static inline unsigned long page_zonenum(struct page *page)
{
	return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

struct zone;
extern struct zone *zone_table[];

static inline struct zone *page_zone(struct page *page)
{
	return zone_table[(page->flags >> ZONETABLE_PGSHIFT) &
			ZONETABLE_MASK];
}

static inline unsigned long page_to_nid(struct page *page)
{
	if (FLAGS_HAS_NODE)
		return (page->flags >> NODES_PGSHIFT) & NODES_MASK;
	else
		return page_zone(page)->zone_pgdat->node_id;
}
static inline unsigned long page_to_section(struct page *page)
{
	return (page->flags >> SECTIONS_PGSHIFT) & SECTIONS_MASK;
}

static inline void set_page_zone(struct page *page, unsigned long zone)
{
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}
static inline void set_page_node(struct page *page, unsigned long node)
{
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}
static inline void set_page_section(struct page *page, unsigned long section)
{
	page->flags &= ~(SECTIONS_MASK << SECTIONS_PGSHIFT);
	page->flags |= (section & SECTIONS_MASK) << SECTIONS_PGSHIFT;
}

static inline void set_page_links(struct page *page, unsigned long zone,
	unsigned long node, unsigned long pfn)
{
	set_page_zone(page, zone);
	set_page_node(page, node);
	set_page_section(page, pfn_to_section_nr(pfn));
}

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*获取低端内存区page的虚拟地址*/
static inline void *lowmem_page_address(struct page *page)
{
	/* 
	 * page_to_pfn(page)<< PAGE_SHIFT返回page的物理地址
	 * 由于位于低端内存，因此虚拟地址和物理地址之间相差一个offset
	 */
	return __va(page_to_pfn(page) << PAGE_SHIFT);
}

#if defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL)
#define HASHED_PAGE_VIRTUAL
#endif

#if defined(WANT_PAGE_VIRTUAL)
#define page_address(page) ((page)->virtual)
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define page_address_init()  do { } while(0)
#endif

#if defined(HASHED_PAGE_VIRTUAL)
void *page_address(struct page *page);
void set_page_address(struct page *page, void *virtual);
void page_address_init(void);
#endif

#if !defined(HASHED_PAGE_VIRTUAL) && !defined(WANT_PAGE_VIRTUAL)
#define page_address(page) lowmem_page_address(page)
#define set_page_address(page, address)  do { } while(0)
#define page_address_init()  do { } while(0)
#endif

/*
 * On an anonymous page mapped into a user virtual memory area,
 * page->mapping points to its anon_vma, not to a struct address_space;
 * with the PAGE_MAPPING_ANON bit set to distinguish it.
 *
 * Please note that, confusingly, "page_mapping" refers to the inode
 * address_space which maps the page from disk; whereas "page_mapped"
 * refers to user virtual address space into which the page is mapped.
 */
#define PAGE_MAPPING_ANON	1

extern struct address_space swapper_space;
static inline struct address_space *page_mapping(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (unlikely(PageSwapCache(page)))
		mapping = &swapper_space;
	else if (unlikely((unsigned long)mapping & PAGE_MAPPING_ANON))
		mapping = NULL;
	return mapping;
}
/*page->mapping的最低位保存是否存储了address_space还是vma->anon_vma*/
static inline int PageAnon(struct page *page)
{
	return ((unsigned long)page->mapping & PAGE_MAPPING_ANON) != 0;
}

/*
 * Return the pagecache index of the passed page.  Regular pagecache pages
 * use ->index whereas swapcache pages use ->private
 */
static inline pgoff_t page_index(struct page *page)
{
	if (unlikely(PageSwapCache(page)))
		return page_private(page);
	return page->index;
}

/*
 * The atomic page->_mapcount, like _count, starts from -1:
 * so that transitions both from it and to it can be tracked,
 * using atomic_inc_and_test and atomic_add_negative(-1).
 */
static inline void reset_page_mapcount(struct page *page)
{
	atomic_set(&(page)->_mapcount, -1);
}

static inline int page_mapcount(struct page *page)
{
	return atomic_read(&(page)->_mapcount) + 1;
}

/*
 * Return true if this page is mapped into pagetables.
 */
static inline int page_mapped(struct page *page)
{
	return atomic_read(&(page)->_mapcount) >= 0;
}

/*
 * Error return values for the *_nopage functions
 */
#define NOPAGE_SIGBUS	(NULL)
#define NOPAGE_OOM	((struct page *) (-1))

/*
 * Different kinds of faults, as returned by handle_mm_fault().
 * Used to decide whether a process gets delivered SIGBUS or
 * just gets major/minor fault counters bumped up.
 */
#define VM_FAULT_OOM	0x00
#define VM_FAULT_SIGBUS	0x01
#define VM_FAULT_MINOR	0x02
#define VM_FAULT_MAJOR	0x03

/* 
 * Special case for get_user_pages.
 * Must be in a distinct bit from the above VM_FAULT_ flags.
 */
#define VM_FAULT_WRITE	0x10

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

extern void show_free_areas(void);

#ifdef CONFIG_SHMEM
struct page *shmem_nopage(struct vm_area_struct *vma,
			unsigned long address, int *type);
int shmem_set_policy(struct vm_area_struct *vma, struct mempolicy *new);
struct mempolicy *shmem_get_policy(struct vm_area_struct *vma,
					unsigned long addr);
int shmem_lock(struct file *file, int lock, struct user_struct *user);
#else
#define shmem_nopage filemap_nopage
#define shmem_lock(a, b, c) 	({0;})	/* always in memory, no need to lock */
#define shmem_set_policy(a, b)	(0)
#define shmem_get_policy(a, b)	(NULL)
#endif
struct file *shmem_file_setup(char *name, loff_t size, unsigned long flags);

int shmem_zero_setup(struct vm_area_struct *);

static inline int can_do_mlock(void)
{
	if (capable(CAP_IPC_LOCK))
		return 1;
	if (current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur != 0)
		return 1;
	return 0;
}
extern int user_shm_lock(size_t, struct user_struct *);
extern void user_shm_unlock(size_t, struct user_struct *);

/*
 * Parameter block passed down to zap_pte_range in exceptional cases.
 */
struct zap_details {
	struct vm_area_struct *nonlinear_vma;	/* Check page->index if set */
	struct address_space *check_mapping;	/* Check page->mapping if set */
	pgoff_t	first_index;			/* Lowest page->index to unmap */
	pgoff_t last_index;			/* Highest page->index to unmap */
	spinlock_t *i_mmap_lock;		/* For unmap_mapping_range: */
	unsigned long truncate_count;		/* Compare vm_truncate_count */
};

unsigned long zap_page_range(struct vm_area_struct *vma, unsigned long address,
		unsigned long size, struct zap_details *);
unsigned long unmap_vmas(struct mmu_gather **tlb,
		struct vm_area_struct *start_vma, unsigned long start_addr,
		unsigned long end_addr, unsigned long *nr_accounted,
		struct zap_details *);
void free_pgd_range(struct mmu_gather **tlb, unsigned long addr,
		unsigned long end, unsigned long floor, unsigned long ceiling);
void free_pgtables(struct mmu_gather **tlb, struct vm_area_struct *start_vma,
		unsigned long floor, unsigned long ceiling);
int copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			struct vm_area_struct *vma);
int zeromap_page_range(struct vm_area_struct *vma, unsigned long from,
			unsigned long size, pgprot_t prot);
void unmap_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen, int even_cows);

static inline void unmap_shared_mapping_range(struct address_space *mapping,
		loff_t const holebegin, loff_t const holelen)
{
	unmap_mapping_range(mapping, holebegin, holelen, 0);
}

extern int vmtruncate(struct inode * inode, loff_t offset);
extern int install_page(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, struct page *page, pgprot_t prot);
extern int install_file_pte(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long addr, unsigned long pgoff, pgprot_t prot);
extern int __handle_mm_fault(struct mm_struct *mm,struct vm_area_struct *vma, unsigned long address, int write_access);

/*
 * 为vma的address分配一个新页表项和页框
 *
 * @mm: 异常发生时正在CPU上运行的进程的内存描述符
 * @vma: 引起异常的线性地址所在线性区的描述符
 * @address: 引起异常的线性地址
 * @write_access: 如果task试图向address写，则置为1，如果task试图在address读或执行，则置为0
 */
static inline int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma, unsigned long address, int write_access)
{
	return __handle_mm_fault(mm, vma, address, write_access) & (~VM_FAULT_WRITE);
}

extern int make_pages_present(unsigned long addr, unsigned long end);
extern int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
void install_arg_page(struct vm_area_struct *, struct page *, unsigned long);

int get_user_pages(struct task_struct *tsk, struct mm_struct *mm, unsigned long start,
		int len, int write, int force, struct page **pages, struct vm_area_struct **vmas);
void print_bad_pte(struct vm_area_struct *, pte_t, unsigned long);

int __set_page_dirty_buffers(struct page *page);
int __set_page_dirty_nobuffers(struct page *page);
int redirty_page_for_writepage(struct writeback_control *wbc,
				struct page *page);
int FASTCALL(set_page_dirty(struct page *page));
int set_page_dirty_lock(struct page *page);
int clear_page_dirty_for_io(struct page *page);

extern unsigned long do_mremap(unsigned long addr,
			       unsigned long old_len, unsigned long new_len,
			       unsigned long flags, unsigned long new_addr);

/*
 * Prototype to add a shrinker callback for ageable caches.
 * 
 * These functions are passed a count `nr_to_scan' and a gfpmask.  They should
 * scan `nr_to_scan' objects, attempting to free them.
 *
 * The callback must return the number of objects which remain in the cache.
 *
 * The callback will be passed nr_to_scan == 0 when the VM is querying the
 * cache size, so a fastpath for that case is appropriate.
 */
typedef int (*shrinker_t)(int nr_to_scan, gfp_t gfp_mask);

/*
 * Add an aging callback.  The int is the number of 'seeks' it takes
 * to recreate one of the objects that these functions age.
 */

#define DEFAULT_SEEKS 2
struct shrinker;
extern struct shrinker *set_shrinker(int, shrinker_t);
extern void remove_shrinker(struct shrinker *shrinker);

int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);
int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long address);

/*
 * The following ifdef needed to get the 4level-fixup.h header to work.
 * Remove it when 4level-fixup.h has been removed.
 */
#if defined(CONFIG_MMU) && !defined(__ARCH_HAS_4LEVEL_HACK)
/*分配pud页，返回address对应的pud页表项的虚拟地址*/
static inline pud_t *pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	/*分配pud页，并将pud页首个pud项物理地址与PAGE_TABLE组合后放到pgd指向的页表项*/ 
	return (unlikely(pgd_none(*pgd)) && __pud_alloc(mm, pgd, address))?
		NULL: pud_offset(pgd, address);
}

/*分配pmd页，返回address对应的pmd页表项的虚拟地址*/ 
static inline pmd_t *pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	/*分配pmd页，并将pmd页首个pmd项物理地址与PAGE_TABLE组合后放到pud指向的页表项*/
	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
		NULL: pmd_offset(pud, address);
}
#endif /* CONFIG_MMU && !__ARCH_HAS_4LEVEL_HACK */

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
/*
 * We tuck a spinlock to guard each pagetable page into its struct page,
 * at page->private, with BUILD_BUG_ON to make sure that this will not
 * overflow into the next struct page (as it might with DEBUG_SPINLOCK).
 * When freeing, reset page->mapping so free_pages_check won't complain.
 */
#define __pte_lockptr(page)	&((page)->u.ptl)
#define pte_lock_init(_page)	do {					\
	spin_lock_init(__pte_lockptr(_page));				\
} while (0)
#define pte_lock_deinit(page)	((page)->mapping = NULL)
#define pte_lockptr(mm, pmd)	({(void)(mm); __pte_lockptr(pmd_page(*(pmd)));})
#else
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
#define pte_lock_init(page)	do {} while (0)
#define pte_lock_deinit(page)	do {} while (0)
#define pte_lockptr(mm, pmd)	({(void)(pmd); &(mm)->page_table_lock;})
#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)

#define pte_alloc_map(mm, pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map(pmd, address))

#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map_lock(mm, pmd, address, ptlp))

#define pte_alloc_kernel(pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))

extern void free_area_init(unsigned long * zones_size);
extern void free_area_init_node(int nid, pg_data_t *pgdat,
	unsigned long * zones_size, unsigned long zone_start_pfn, 
	unsigned long *zholes_size);
extern void memmap_init_zone(unsigned long, int, unsigned long, unsigned long);
extern void setup_per_zone_pages_min(void);
extern void mem_init(void);
extern void show_mem(void);
extern void si_meminfo(struct sysinfo * val);
extern void si_meminfo_node(struct sysinfo *val, int nid);

#ifdef CONFIG_NUMA
extern void setup_per_cpu_pageset(void);
#else
static inline void setup_per_cpu_pageset(void) {}
#endif

/* prio_tree.c */
void vma_prio_tree_add(struct vm_area_struct *, struct vm_area_struct *old);
void vma_prio_tree_insert(struct vm_area_struct *, struct prio_tree_root *);
void vma_prio_tree_remove(struct vm_area_struct *, struct prio_tree_root *);
struct vm_area_struct *vma_prio_tree_next(struct vm_area_struct *vma,
	struct prio_tree_iter *iter);

#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )

static inline void vma_nonlinear_insert(struct vm_area_struct *vma,
					struct list_head *list)
{
	vma->shared.vm_set.parent = NULL;
	list_add_tail(&vma->shared.vm_set.list, list);
}

/* mmap.c */
extern int __vm_enough_memory(long pages, int cap_sys_admin);
extern void vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert);
extern struct vm_area_struct *vma_merge(struct mm_struct *,
	struct vm_area_struct *prev, unsigned long addr, unsigned long end,
	unsigned long vm_flags, struct anon_vma *, struct file *, pgoff_t,
	struct mempolicy *);
extern struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *);
extern int split_vma(struct mm_struct *,
	struct vm_area_struct *, unsigned long addr, int new_below);
extern int insert_vm_struct(struct mm_struct *, struct vm_area_struct *);
extern void __vma_link_rb(struct mm_struct *, struct vm_area_struct *,
	struct rb_node **, struct rb_node *);
extern void unlink_file_vma(struct vm_area_struct *);
extern struct vm_area_struct *copy_vma(struct vm_area_struct **,
	unsigned long addr, unsigned long len, pgoff_t pgoff);
extern void exit_mmap(struct mm_struct *);
extern int may_expand_vm(struct mm_struct *mm, unsigned long npages);

extern unsigned long get_unmapped_area(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);

extern unsigned long do_mmap_pgoff(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long pgoff);

/*
 * 文件映射或匿名映射,如果是匿名映射则file与pgoff为空
 *
 * @file: 表示新的线性区将把一个文件映射到内存
 * @offset：文件内的偏移量，要映射文件部分的第一个字符 
 * @addr: 指定从何处开始查找一个空闲的线性区
 * @len: 线性地址区间的长度
 * @prot: 这个线性区所包含页的权限
 * @flag: 指定线性区的其它标志
 */
static inline unsigned long do_mmap(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset)
{
	unsigned long ret = -EINVAL;
	if ((offset + PAGE_ALIGN(len)) < offset)
		goto out;
	if (!(offset & ~PAGE_MASK))
		ret = do_mmap_pgoff(file, addr, len, prot, flag, offset >> PAGE_SHIFT);
out:
	return ret;
}

extern int do_munmap(struct mm_struct *, unsigned long, size_t);

extern unsigned long do_brk(unsigned long, unsigned long);

/* filemap.c */
extern unsigned long page_unuse(struct page *);
extern void truncate_inode_pages(struct address_space *, loff_t);

/* generic vm_area_ops exported for stackable file systems */
extern struct page *filemap_nopage(struct vm_area_struct *, unsigned long, int *);
extern int filemap_populate(struct vm_area_struct *, unsigned long,
		unsigned long, pgprot_t, unsigned long, int);

/* mm/page-writeback.c */
int write_one_page(struct page *page, int wait);

/* readahead.c */
#define VM_MAX_READAHEAD	128	/* kbytes */
#define VM_MIN_READAHEAD	16	/* kbytes (includes current page) */
#define VM_MAX_CACHE_HIT    	256	/* max pages in a row in cache before
					 * turning readahead off */

int do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read);
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
			unsigned long offset, unsigned long nr_to_read);
unsigned long  page_cache_readahead(struct address_space *mapping,
			  struct file_ra_state *ra,
			  struct file *filp,
			  unsigned long offset,
			  unsigned long size);
void handle_ra_miss(struct address_space *mapping, 
		    struct file_ra_state *ra, pgoff_t offset);
unsigned long max_sane_readahead(unsigned long nr);

/* Do stack extension */
extern int expand_stack(struct vm_area_struct *vma, unsigned long address);
extern int expand_upwards(struct vm_area_struct *vma, unsigned long address);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
extern struct vm_area_struct * find_vma(struct mm_struct * mm, unsigned long addr);
extern struct vm_area_struct * find_vma_prev(struct mm_struct * mm, unsigned long addr,
					     struct vm_area_struct **pprev);

/* Look up the first VMA which intersects the interval start_addr..end_addr-1,
   NULL if none.  Assume start_addr < end_addr. */
/*查找一个在给定区间内的线性区相重叠的线性区*/
static inline struct vm_area_struct * find_vma_intersection(struct mm_struct * mm, unsigned long start_addr, unsigned long end_addr)
{
	/*返回vma_end > start_addr的第一个线性区的描述符*/
	struct vm_area_struct * vma = find_vma(mm,start_addr);

	if (vma && end_addr <= vma->vm_start)
		vma = NULL;
	return vma;
}

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

struct vm_area_struct *find_extend_vma(struct mm_struct *, unsigned long addr);
struct page *vmalloc_to_page(void *addr);
unsigned long vmalloc_to_pfn(void *addr);
int remap_pfn_range(struct vm_area_struct *, unsigned long addr,
			unsigned long pfn, unsigned long size, pgprot_t);

struct page *follow_page(struct mm_struct *, unsigned long address,
			unsigned int foll_flags);
#define FOLL_WRITE	0x01	/* check pte is writable */
#define FOLL_TOUCH	0x02	/* mark page accessed */
#define FOLL_GET	0x04	/* do get_page on page */
#define FOLL_ANON	0x08	/* give ZERO_PAGE if no pgtable */

#ifdef CONFIG_PROC_FS
void vm_stat_account(struct mm_struct *, unsigned long, struct file *, long);
#else
static inline void vm_stat_account(struct mm_struct *mm,
			unsigned long flags, struct file *file, long pages)
{
}
#endif /* CONFIG_PROC_FS */

#ifndef CONFIG_DEBUG_PAGEALLOC
static inline void
kernel_map_pages(struct page *page, int numpages, int enable)
{
}
#endif

extern struct vm_area_struct *get_gate_vma(struct task_struct *tsk);
#ifdef	__HAVE_ARCH_GATE_AREA
int in_gate_area_no_task(unsigned long addr);
int in_gate_area(struct task_struct *task, unsigned long addr);
#else
int in_gate_area_no_task(unsigned long addr);
#define in_gate_area(task, addr) ({(void)task; in_gate_area_no_task(addr);})
#endif	/* __HAVE_ARCH_GATE_AREA */

/* /proc/<pid>/oom_adj set to -17 protects from the oom-killer */
#define OOM_DISABLE -17

#endif /* __KERNEL__ */
#endif /* _LINUX_MM_H */
