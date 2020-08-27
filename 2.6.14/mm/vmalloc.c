/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 *  Numa awareness, Christoph Lameter, SGI, June 2005
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/vmalloc.h>

#include <asm/uaccess.h>
#include <asm/tlbflush.h>


DEFINE_RWLOCK(vmlist_lock);
/*保存vm_struct链表的第一个元素地址*/
struct vm_struct *vmlist;

static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static inline void vunmap_pmd_range(pud_t *pud, unsigned long addr,
						unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		vunmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void vunmap_pud_range(pgd_t *pgd, unsigned long addr,
						unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		vunmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

void unmap_vm_area(struct vm_struct *area)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = (unsigned long) area->addr;
	unsigned long end = addr + area->size;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	flush_cache_vunmap(addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_kernel_range((unsigned long) area->addr, end);
}

static int vmap_pte_range(pmd_t *pmd, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pte_t *pte;

	/*分配一个pte目录项*/
	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		struct page *page = **pages;
		WARN_ON(!pte_none(*pte));
		if (!page)
			return -ENOMEM;
		set_pte_at(&init_mm, addr, pte, mk_pte(page, prot));
		(*pages)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static inline int vmap_pmd_range(pud_t *pud, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pmd_t *pmd;
	unsigned long next;

	/*分配一个pmd目录项*/
	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		/*返回addr所属pmd项的下一个pmd项的地址范围的起始地址*/
		next = pmd_addr_end(addr, end);
		if (vmap_pte_range(pmd, addr, next, prot, pages))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int vmap_pud_range(pgd_t *pgd, unsigned long addr,
			unsigned long end, pgprot_t prot, struct page ***pages)
{
	pud_t *pud;
	unsigned long next;

	/*分配pud页表项，返回address对应的pud页表项的虚拟地址*/
	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		/*返回addr所属pud项的下一个pud项的地址范围的起始地址*/
		next = pud_addr_end(addr, end);
		if (vmap_pmd_range(pud, addr, next, prot, pages))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}
/*
 * 将分配的page映射到vmalloc非连续线性区???
 *
 * @area: vm_struct描述符
 * @prot: 已分配页框的保护位
 * @pages: 指向页描述符指针数组
 */
int map_vm_area(struct vm_struct *area, pgprot_t prot, struct page ***pages)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = (unsigned long) area->addr;
	/*area->size包含PAGE_SIZE保护区*/
	unsigned long end = addr + area->size - PAGE_SIZE;
	int err;

	BUG_ON(addr >= end);
	/*
	 * 根据地址addr获取内核的pgd页表项,页目录基址位于init_mm.pgd也就是swapper_pg_dir
	 * 由于在init_mm中通过vmalloc建立的映射区间，因此通过本进程mm_struct中访问该区间地址时发生pagefault
	 * 通过do_page_fault的vmalloc_fault来修正
	 *
	 */ 
	pgd = pgd_offset_k(addr);
	do {
		/*返回addr所属pgd项的下一个pgd项的地址范围的起始地址*/
		next = pgd_addr_end(addr, end);
		/*为addr创建pgd页表项，并对下一个地址next创建pgd页表项*/
		err = vmap_pud_range(pgd, addr, next, prot, pages);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);
	flush_cache_vmap((unsigned long) area->addr, end);
	return err;
}
/*在start~end区间获取大小为size的vmalloc区域*/
struct vm_struct *__get_vm_area_node(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end, int node)
{
	struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	if (flags & VM_IOREMAP) {
		int bit = fls(size);

		if (bit > IOREMAP_MAX_ORDER)
			bit = IOREMAP_MAX_ORDER;
		else if (bit < PAGE_SHIFT)
			bit = PAGE_SHIFT;

		align = 1ul << bit;
	}
	/*将地址对齐*/
	addr = ALIGN(start, align);
	size = PAGE_ALIGN(size);

	/*分配一个vm_struct*/
	area = kmalloc_node(sizeof(*area), GFP_KERNEL, node);
	if (unlikely(!area))
		return NULL;

	if (unlikely(!size)) {
		kfree (area);
		return NULL;
	}

	/*
	 * We always allocate a guard page.
	 */
	size += PAGE_SIZE;

	write_lock(&vmlist_lock);
	/*遍历vmlist链表，找到符合条件的vmalloc区*/
	for (p = &vmlist; (tmp = *p) != NULL ;p = &tmp->next) {
		if ((unsigned long)tmp->addr < addr) {
			if((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + 
					     (unsigned long)tmp->addr, align);
			continue;
		}
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long)tmp->addr)
			goto found;
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:
	/*如果找到vmalloc区域，则对分配的vm_struct初始化*/
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	write_unlock(&vmlist_lock);

	return area;

out:
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

/*在start~end区间获取大小为size的vmalloc区域*/
struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end)
{
	return __get_vm_area_node(size, flags, start, end, -1);
}

/**
 *	get_vm_area  -  reserve a contingous kernel virtual area
 *
 *	@size:		size of the area
 *	@flags:		%VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 *	Search an area of @size in the kernel virtual mapping area,
 *	and reserved it for out purposes.  Returns the area descriptor
 *	on success or %NULL on failure.
 */
/*在VMALLOC_START~VMALLOC_END区间获取一段大小为size的非连续区域*/
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area(size, flags, VMALLOC_START, VMALLOC_END);
}

struct vm_struct *get_vm_area_node(unsigned long size, unsigned long flags, int node)
{
	return __get_vm_area_node(size, flags, VMALLOC_START, VMALLOC_END, node);
}

/* Caller must hold vmlist_lock */
struct vm_struct *__remove_vm_area(void *addr)
{
	struct vm_struct **p, *tmp;

	for (p = &vmlist ; (tmp = *p) != NULL ;p = &tmp->next) {
		 if (tmp->addr == addr)
			 goto found;
	}
	return NULL;

found:
	unmap_vm_area(tmp);
	*p = tmp->next;

	/*
	 * Remove the guard page.
	 */
	tmp->size -= PAGE_SIZE;
	return tmp;
}

/**
 *	remove_vm_area  -  find and remove a contingous kernel virtual area
 *
 *	@addr:		base address
 *
 *	Search for the kernel VM area starting at @addr, and remove it.
 *	This function returns the found VM area, but using it is NOT safe
 *	on SMP machines, except for its size or flags.
 */
struct vm_struct *remove_vm_area(void *addr)
{
	struct vm_struct *v;
	write_lock(&vmlist_lock);
	v = __remove_vm_area(addr);
	write_unlock(&vmlist_lock);
	return v;
}

/*
 * @deallocate_pages: 置位表示映射到内存区的页框应当被释放到分区页框分配器
 */
void __vunmap(void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;

	if ((PAGE_SIZE-1) & (unsigned long)addr) {
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		WARN_ON(1);
		return;
	}

	/*得到vm_struct描述符，并清除非连续内存区中的线性地址对应的内核页表项???*/
	area = remove_vm_area(addr);
	if (unlikely(!area)) {
		printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		WARN_ON(1);
		return;
	}

	if (deallocate_pages) {
		int i;
		
		/*释放页框*/
		for (i = 0; i < area->nr_pages; i++) {
			if (unlikely(!area->pages[i]))
				BUG();
			__free_page(area->pages[i]);
		}

		/*释放area->pages数组本身*/
		if (area->nr_pages > PAGE_SIZE/sizeof(struct page *))
			vfree(area->pages);
		else
			kfree(area->pages);
	}

	/*释放vm_struct*/
	kfree(area);
	return;
}

/**
 *	vfree  -  release memory allocated by vmalloc()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr, as
 *	obtained from vmalloc(), vmalloc_32() or __vmalloc(). If @addr is
 *	NULL, no operation is performed.
 *
 *	Must not be called in interrupt context.
 */
/*释放通过vmalloc创建的非连续内存区*/
void vfree(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 1);
}
EXPORT_SYMBOL(vfree);

/**
 *	vunmap  -  release virtual mapping obtained by vmap()
 *
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr,
 *	which was created from the page array passed to vmap().
 *
 *	Must not be called in interrupt context.
 */
void vunmap(void *addr)
{
	BUG_ON(in_interrupt());
	__vunmap(addr, 0);
}
EXPORT_SYMBOL(vunmap);

/**
 *	vmap  -  map an array of pages into virtually contiguous space
 *
 *	@pages:		array of page pointers
 *	@count:		number of pages to map
 *	@flags:		vm_area->flags
 *	@prot:		page protection for the mapping
 *
 *	Maps @count pages from @pages into contiguous kernel virtual
 *	space.
 */
void *vmap(struct page **pages, unsigned int count,
		unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;

	if (count > num_physpages)
		return NULL;

	area = get_vm_area((count << PAGE_SHIFT), flags);
	if (!area)
		return NULL;
	if (map_vm_area(area, prot, &pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
}
EXPORT_SYMBOL(vmap);

/*为vmalloc区域分配page*/
void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
				pgprot_t prot, int node)
{
	struct page **pages;
	unsigned int nr_pages, array_size, i;

	/*获取要分配的page页数*/
	nr_pages = (area->size - PAGE_SIZE) >> PAGE_SHIFT;
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	if (array_size > PAGE_SIZE)
		pages = __vmalloc_node(array_size, gfp_mask, PAGE_KERNEL, node);
	else
		pages = kmalloc_node(array_size, (gfp_mask & ~__GFP_HIGHMEM), node);
	area->pages = pages;
	if (!area->pages) {
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}
	memset(area->pages, 0, array_size);

	/*分配nr_pages个page页框*/
	for (i = 0; i < area->nr_pages; i++) {
		if (node < 0)
			area->pages[i] = alloc_page(gfp_mask);
		else
			area->pages[i] = alloc_pages_node(node, gfp_mask, 0);
		if (unlikely(!area->pages[i])) {
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
	}
	
	/*将分配的page映射到vmalloc非连续线性区*/
	if (map_vm_area(area, prot, &pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

void *__vmalloc_area(struct vm_struct *area, gfp_t gfp_mask, pgprot_t prot)
{
	return __vmalloc_area_node(area, gfp_mask, prot, -1);
}

/**
 *	__vmalloc_node  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *	@gfp_mask:	flags for the page level allocator
 *	@prot:		protection mask for the allocated pages
 *	@node		node to use for allocation or -1
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator with @gfp_mask flags.  Map them into contiguous
 *	kernel virtual space, using a pagetable protection of @prot.
 */
void *__vmalloc_node(unsigned long size, gfp_t gfp_mask, pgprot_t prot,
			int node)
{
	struct vm_struct *area;

	/*4096对齐*/
	size = PAGE_ALIGN(size);
	if (!size || (size >> PAGE_SHIFT) > num_physpages)
		return NULL;

	/*创建新的vm_struct描述符，在VMALLOC_START~VMALLOC_END区间获取一段大小为size的非连续区域*/
	area = get_vm_area_node(size, VM_ALLOC, node);
	if (!area)
		return NULL;

	return __vmalloc_area_node(area, gfp_mask, prot, node);
}
EXPORT_SYMBOL(__vmalloc_node);

void *__vmalloc(unsigned long size, gfp_t gfp_mask, pgprot_t prot)
{
	return __vmalloc_node(size, gfp_mask, prot, -1);
}
EXPORT_SYMBOL(__vmalloc);

/**
 *	vmalloc  -  allocate virtually contiguous memory
 *
 *	@size:		allocation size
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
void *vmalloc(unsigned long size)
{
       return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
}
EXPORT_SYMBOL(vmalloc);

/**
 *	vmalloc_node  -  allocate memory on a specific node
 *
 *	@size:		allocation size
 *	@node;		numa node
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator and map them into contiguous kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */
void *vmalloc_node(unsigned long size, int node)
{
       return __vmalloc_node(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL, node);
}
EXPORT_SYMBOL(vmalloc_node);

#ifndef PAGE_KERNEL_EXEC
# define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

/**
 *	vmalloc_exec  -  allocate virtually contiguous, executable memory
 *
 *	@size:		allocation size
 *
 *	Kernel-internal function to allocate enough pages to cover @size
 *	the page level allocator and map them into contiguous and
 *	executable kernel virtual space.
 *
 *	For tight cotrol over page level allocator and protection flags
 *	use __vmalloc() instead.
 */

void *vmalloc_exec(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
}

/**
 *	vmalloc_32  -  allocate virtually contiguous memory (32bit addressable)
 *
 *	@size:		allocation size
 *
 *	Allocate enough 32bit PA addressable pages to cover @size from the
 *	page level allocator and map them into contiguous kernel virtual space.
 */
void *vmalloc_32(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL);
}
EXPORT_SYMBOL(vmalloc_32);

long vread(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}
