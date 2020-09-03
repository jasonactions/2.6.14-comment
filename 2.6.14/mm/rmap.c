/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins <hugh@veritas.com> 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_sem	(while writing or truncating, not reading or faulting)
 *   inode->i_alloc_sem
 *
 * When a page fault occurs in writing from user to file, down_read
 * of mmap_sem nests within i_sem; in sys_msync, i_sem nests within
 * down_read of mmap_sem; i_sem and down_write of mmap_sem are never
 * taken together; in truncation, i_sem is taken outermost.
 *
 * mm->mmap_sem
 *   page->flags PG_locked (lock_page)
 *     mapping->i_mmap_lock
 *       anon_vma->lock
 *         mm->page_table_lock or pte_lock
 *           zone->lru_lock (in mark_page_accessed)
 *           swap_lock (in swap_duplicate, swap_info_get)
 *             mmlist_lock (in mmput, drain_mmlist and others)
 *             mapping->private_lock (in __set_page_dirty_buffers)
 *             inode_lock (in set_page_dirty's __mark_inode_dirty)
 *               sb_lock (within inode_lock in fs/fs-writeback.c)
 *               mapping->tree_lock (widely used, in set_page_dirty,
 *                         in arch-dependent flush_dcache_mmap_lock,
 *                         within inode_lock in __sync_single_inode)
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>

#include <asm/tlbflush.h>

//#define RMAP_DEBUG /* can be enabled only for debugging */

kmem_cache_t *anon_vma_cachep;

static inline void validate_anon_vma(struct vm_area_struct *find_vma)
{
#ifdef RMAP_DEBUG
	struct anon_vma *anon_vma = find_vma->anon_vma;
	struct vm_area_struct *vma;
	unsigned int mapcount = 0;
	int found = 0;

	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		mapcount++;
		BUG_ON(mapcount > 100000);
		if (vma == find_vma)
			found = 1;
	}
	BUG_ON(!found);
#endif
}

/* This must be called under the mmap_sem. */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated, *locked;

		anon_vma = find_mergeable_anon_vma(vma);
		if (anon_vma) {
			allocated = NULL;
			locked = anon_vma;
			spin_lock(&locked->lock);
		} else {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				return -ENOMEM;
			allocated = anon_vma;
			locked = NULL;
		}

		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		if (likely(!vma->anon_vma)) {
			vma->anon_vma = anon_vma;
			list_add(&vma->anon_vma_node, &anon_vma->head);
			allocated = NULL;
		}
		spin_unlock(&mm->page_table_lock);

		if (locked)
			spin_unlock(&locked->lock);
		if (unlikely(allocated))
			anon_vma_free(allocated);
	}
	return 0;
}

void __anon_vma_merge(struct vm_area_struct *vma, struct vm_area_struct *next)
{
	BUG_ON(vma->anon_vma != next->anon_vma);
	list_del(&next->anon_vma_node);
}

void __anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	/*说明线性区是匿名的*/
	if (anon_vma) {
		list_add(&vma->anon_vma_node, &anon_vma->head);
		validate_anon_vma(vma);
	}
}

void anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma) {
		spin_lock(&anon_vma->lock);
		list_add(&vma->anon_vma_node, &anon_vma->head);
		validate_anon_vma(vma);
		spin_unlock(&anon_vma->lock);
	}
}

/*将匿名线性区从vma->anon_vma链表删除*/
void anon_vma_unlink(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int empty;

	if (!anon_vma)
		return;

	spin_lock(&anon_vma->lock);
	validate_anon_vma(vma);
	list_del(&vma->anon_vma_node);

	/* We must garbage collect the anon_vma if it's empty */
	empty = list_empty(&anon_vma->head);
	spin_unlock(&anon_vma->lock);

	if (empty)
		anon_vma_free(anon_vma);
}

static void anon_vma_ctor(void *data, kmem_cache_t *cachep, unsigned long flags)
{
	if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
						SLAB_CTOR_CONSTRUCTOR) {
		struct anon_vma *anon_vma = data;

		spin_lock_init(&anon_vma->lock);
		INIT_LIST_HEAD(&anon_vma->head);
	}
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor, NULL);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is
 * tricky: page_lock_anon_vma rely on RCU to guard against the races.
 */
/*获取匿名页page所在线性区的链表头*/
static struct anon_vma *page_lock_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) page->mapping;
	if (!(anon_mapping & PAGE_MAPPING_ANON))
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	spin_lock(&anon_vma->lock);
out:
	rcu_read_unlock();
	return anon_vma;
}

/*
 * At what user virtual address is page expected in vma?
 */
/*通过vma_start和page->index来获取page的线性地址*/
static inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	/*此处page->index保存了page位于vma的页索引*/
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	unsigned long address;

	address = vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end)) {
		/* page should be within any vma from prio_tree_next */
		BUG_ON(!PageAnon(page));
		return -EFAULT;
	}
	return address;
}

/*
 * At what user virtual address is page expected in vma? checking that the
 * page matches the vma: currently only used by unuse_process, on anon pages.
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	if (PageAnon(page)) {
		if ((void *)vma->anon_vma !=
		    (void *)page->mapping - PAGE_MAPPING_ANON)
			return -EFAULT;
	} else if (page->mapping && !(vma->vm_flags & VM_NONLINEAR)) {
		if (vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	return vma_address(page, vma);
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * On success returns with pte mapped and locked.
 */
/*获取page的线性地址address对应的页表项,并检查页表项是否合法，合法则返回页表项*/
pte_t *page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}
	pte_unmap_unlock(pte, ptl);
	return NULL;
}

/*
 * Subfunctions of page_referenced: page_referenced_one called
 * repeatedly from either page_referenced_anon or page_referenced_file.
 */
/*返回page的reference*/
static int page_referenced_one(struct page *page,
	struct vm_area_struct *vma, unsigned int *mapcount, int ignore_token)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int referenced = 0;

	/*获取page映射到vma的线性地址*/
	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;

	/*返回page的pte*/
	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)
		goto out;

	if (ptep_clear_flush_young(vma, address, pte))
		referenced++;

	/* Pretend the page is referenced if the task has the
	   swap token and is in the middle of a page fault. */
	/*如果持有swap token则认可，将referenced加1*/
	if (mm != current->mm && !ignore_token && has_swap_token(mm) &&
			rwsem_is_locked(&mm->mmap_sem))
		referenced++;

	(*mapcount)--;
	pte_unmap_unlock(pte, ptl);
out:
	return referenced;
}

/*获取匿名页的reference*/
static int page_referenced_anon(struct page *page, int ignore_token)
{
	unsigned int mapcount;
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int referenced = 0;

	/*获取匿名页page所在线性区的链表头*/
	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return referenced;

	/*获取引用page的页表项的数目*/
	mapcount = page_mapcount(page);
	/*遍历引用此匿名页的所有vma,累加referenced*/
	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		referenced += page_referenced_one(page, vma, &mapcount,
							ignore_token);
		if (!mapcount)
			break;
	}
	spin_unlock(&anon_vma->lock);
	return referenced;
}

/**
 * page_referenced_file - referenced check for object-based rmap
 * @page: the page we're checking references on.
 *
 * For an object-based mapped page, find all the places it is mapped and
 * check/clear the referenced flag.  This is done by following the page->mapping
 * pointer, then walking the chain of vmas it holds.  It returns the number
 * of references it found.
 *
 * This function is only called from page_referenced for object-based pages.
 */
/*获取文件映射页的referenced*/
static int page_referenced_file(struct page *page, int ignore_token)
{
	unsigned int mapcount;
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int referenced = 0;

	/*
	 * The caller's checks on page->mapping and !PageAnon have made
	 * sure that this is a file page: the check for page->mapping
	 * excludes the case just before it gets set on an anon page.
	 */
	BUG_ON(PageAnon(page));

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_lock.
	 */
	BUG_ON(!PageLocked(page));

	spin_lock(&mapping->i_mmap_lock);

	/*
	 * i_mmap_lock does not stabilize mapcount at all, but mapcount
	 * is more likely to be accurate if we note it after spinning.
	 */
	mapcount = page_mapcount(page);

	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if ((vma->vm_flags & (VM_LOCKED|VM_MAYSHARE))
				  == (VM_LOCKED|VM_MAYSHARE)) {
			referenced++;
			break;
		}
		referenced += page_referenced_one(page, vma, &mapcount,
							ignore_token);
		if (!mapcount)
			break;
	}

	spin_unlock(&mapping->i_mmap_lock);
	return referenced;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 */
int page_referenced(struct page *page, int is_locked, int ignore_token)
{
	int referenced = 0;

	if (!swap_token_default_timeout)
		ignore_token = 1;

	if (page_test_and_clear_young(page))
		referenced++;

	if (TestClearPageReferenced(page))
		referenced++;

	if (page_mapped(page) && page->mapping) {
		if (PageAnon(page))
			/*获取匿名页的reference*/
			referenced += page_referenced_anon(page, ignore_token);
		else if (is_locked)
			/*获取文件映射页的referenced*/ 
			referenced += page_referenced_file(page, ignore_token);
		else if (TestSetPageLocked(page))
			referenced++;
		else {
			if (page->mapping)
				referenced += page_referenced_file(page,
								ignore_token);
			unlock_page(page);
		}
	}
	return referenced;
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * The caller needs to hold the pte lock.
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	if (atomic_inc_and_test(&page->_mapcount)) {
		struct anon_vma *anon_vma = vma->anon_vma;

		BUG_ON(!anon_vma);
		anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
		page->mapping = (struct address_space *) anon_vma;

		page->index = linear_page_index(vma, address);

		inc_page_state(nr_mapped);
	}
	/* else checking page index and mapping is racy */
}

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page)
{
	BUG_ON(PageAnon(page));
	BUG_ON(!pfn_valid(page_to_pfn(page)));

	if (atomic_inc_and_test(&page->_mapcount))
		inc_page_state(nr_mapped);
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page: page to remove mapping from
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page)
{
	if (atomic_add_negative(-1, &page->_mapcount)) {
		BUG_ON(page_mapcount(page) < 0);
		/*
		 * It would be tidy to reset the PageAnon mapping here,
		 * but that might overwrite a racing page_add_anon_rmap
		 * which increments mapcount after us but sets mapping
		 * before us: so leave the reset to free_hot_cold_page,
		 * and remember that it's only reliable while mapped.
		 * Leaving it set also helps swapoff to reinstate ptes
		 * faster for those pages still in swapcache.
		 */
		if (page_test_and_clear_dirty(page))
			set_page_dirty(page);
		dec_page_state(nr_mapped);
	}
}

/*
 * Subfunctions of try_to_unmap: try_to_unmap_one called
 * repeatedly from either try_to_unmap_anon or try_to_unmap_file.
 */
/*根据page和vma找到pte，清空此pte*/
static int try_to_unmap_one(struct page *page, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;

	/*获取待回收page的线性地址*/
	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;

	/*获取page的线性地址address对应的页表项,并检查页表项是否合法，如果不合法返回0*/	
	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)
		goto out;

	/*
	 * If the page is mlock()d, we cannot swap it out.
	 * If it's recently referenced (perhaps page_referenced
	 * skipped over this mm) then we should reactivate it.
	 *
	 * Pages belonging to VM_RESERVED regions should not happen here.
	 */
	/*页被锁定或保留不能回收*/
	if ((vma->vm_flags & (VM_LOCKED|VM_RESERVED)) ||
			/*页在用，不能回收*/
			ptep_clear_flush_young(vma, address, pte)) {
		ret = SWAP_FAIL;
		goto out_unmap;
	}

	/* Nuke the page table entry. */
	flush_cache_page(vma, address, page_to_pfn(page));
	/*清空pte,并刷新tlb*/
	pteval = ptep_clear_flush(vma, address, pte);

	/* Move the dirty bit to the physical page now the pte is gone. */
	if (pte_dirty(pteval))
		set_page_dirty(page);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);
	
	/*如果目标页是匿名页*/
	if (PageAnon(page)) {
		swp_entry_t entry = { .val = page_private(page) };
		/*
		 * Store the swap location in the pte.
		 * See handle_pte_fault() ...
		 */
		BUG_ON(!PageSwapCache(page));
		swap_duplicate(entry);
		if (list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			if (list_empty(&mm->mmlist))
				list_add(&mm->mmlist, &init_mm.mmlist);
			spin_unlock(&mmlist_lock);
		}
		/*将换出页标识符(标识了交换区的索引和页槽索引)插入页表项，以便将来访问时将该页换入*/
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
		BUG_ON(pte_file(*pte));
		/*递减匿名页计数器*/
		dec_mm_counter(mm, anon_rss);
	} else
		/*递减文件页计数器*/
		dec_mm_counter(mm, file_rss);

	/*递减引用此页框的页表项数目*/
	page_remove_rmap(page);
	/*递减对page的页框引用计数*/
	page_cache_release(page);

out_unmap:
	/*释放临时映射，page_check_address->pte_offset_map会创建临时映射*/
	pte_unmap_unlock(pte, ptl);
out:
	return ret;
}

/*
 * objrmap doesn't work for nonlinear VMAs because the assumption that
 * offset-into-file correlates with offset-into-virtual-addresses does not hold.
 * Consequently, given a particular page and its ->index, we cannot locate the
 * ptes which are mapping that page without an exhaustive linear search.
 *
 * So what this code does is a mini "virtual scan" of each nonlinear VMA which
 * maps the file to which the target page belongs.  The ->vm_private_data field
 * holds the current cursor into that scan.  Successive searches will circulate
 * around the vma's virtual address space.
 *
 * So as more replacement pressure is applied to the pages in a nonlinear VMA,
 * more scanning pressure is placed against them as well.   Eventually pages
 * will become fully unmapped and are eligible for eviction.
 *
 * For very sparsely populated VMAs this is a little inefficient - chances are
 * there there won't be many ptes located within the scan cluster.  In this case
 * maybe we could scan further - to the end of the pte page, perhaps.
 */
#define CLUSTER_SIZE	min(32*PAGE_SIZE, PMD_SIZE)
#define CLUSTER_MASK	(~(CLUSTER_SIZE - 1))

/*尝试清除文件映射的非线性映射vma的CLUSTER_SIZE个地址的页表项*/
static void try_to_unmap_cluster(unsigned long cursor,
	unsigned int *mapcount, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned long address;
	unsigned long end;
	unsigned long pfn;

	address = (vma->vm_start + cursor) & CLUSTER_MASK;
	end = address + CLUSTER_SIZE;
	if (address < vma->vm_start)
		address = vma->vm_start;
	if (end > vma->vm_end)
		end = vma->vm_end;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return;

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	for (; address < end; pte++, address += PAGE_SIZE) {
		if (!pte_present(*pte))
			continue;

		pfn = pte_pfn(*pte);
		if (unlikely(!pfn_valid(pfn))) {
			print_bad_pte(vma, *pte, address);
			continue;
		}

		page = pfn_to_page(pfn);
		BUG_ON(PageAnon(page));

		if (ptep_clear_flush_young(vma, address, pte))
			continue;

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pfn);
		pteval = ptep_clear_flush(vma, address, pte);

		/* If nonlinear, store the file page offset in the pte. */
		if (page->index != linear_page_index(vma, address))
			set_pte_at(mm, address, pte, pgoff_to_pte(page->index));

		/* Move the dirty bit to the physical page now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty(page);

		page_remove_rmap(page);
		page_cache_release(page);
		dec_mm_counter(mm, file_rss);
		(*mapcount)--;
	}
	pte_unmap_unlock(pte - 1, ptl);
}

/*清空引用此匿名页的所有页表项*/
static int try_to_unmap_anon(struct page *page)
{
	struct anon_vma *anon_vma;
	struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

	/*
	 * 获取引用page的所有vma所在的链表头
	 * 注：anon_vma链表可能存有不包含目标页的线性区
	 */
	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return ret;

	/*遍历anon_vma链表, 释放页表项成功或返回SWAP_FAIL则退出*/
	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		ret = try_to_unmap_one(page, vma);
		if (ret == SWAP_FAIL || !page_mapped(page))
			break;
	}
	spin_unlock(&anon_vma->lock);
	return ret;
}

/**
 * try_to_unmap_file - unmap file page using the object-based rmap method
 * @page: the page to unmap
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * This function is only called from try_to_unmap for object-based pages.
 */
/*清空page的所有文件映射pte*/
static int try_to_unmap_file(struct page *page)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = SWAP_AGAIN;
	unsigned long cursor;
	unsigned long max_nl_cursor = 0;
	unsigned long max_nl_size = 0;
	unsigned int mapcount;

	spin_lock(&mapping->i_mmap_lock);
	/*mapping->i_mmap为搜索树的根,对每一个vma执行try_to_unmap_one清空线性映射的线性区中引用page的pte*/
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		ret = try_to_unmap_one(page, vma);
		if (ret == SWAP_FAIL || !page_mapped(page))
			goto out;
	}

	/*如果不存在非线性映射，则直接退出*/
	if (list_empty(&mapping->i_mmap_nonlinear))
		goto out;
	
	/*
	 * 如果存在非线性映射
	 * 由于page->index存放文件中页的位置,try_to_unmap_one无法确定页的线性地址,无法获取pte地址
	 * 通过遍历文件的非线性映射链表，找到每一个非线性映射线性区,确定最大扫描cursor和最大扫描size
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
		if (vma->vm_flags & (VM_LOCKED|VM_RESERVED))
			continue;
		/*vm_private_data保存当前非线性映射线性区vma的当前扫描位置*/
		cursor = (unsigned long) vma->vm_private_data;
		if (cursor > max_nl_cursor)
			max_nl_cursor = cursor;
		cursor = vma->vm_end - vma->vm_start;
		if (cursor > max_nl_size)
			max_nl_size = cursor;
	}

	if (max_nl_size == 0) {	/* any nonlinears locked or reserved */
		ret = SWAP_FAIL;
		goto out;
	}

	/*
	 * We don't try to search for this page in the nonlinear vmas,
	 * and page_referenced wouldn't have found it anyway.  Instead
	 * just walk the nonlinear vmas trying to age and unmap some.
	 * The mapcount of the page we came in with is irrelevant,
	 * but even so use it as a guide to how hard we should try?
	 */
	/*确定引用页框page的页表项数目*/
	mapcount = page_mapcount(page);
	if (!mapcount)
		goto out;
	cond_resched_lock(&mapping->i_mmap_lock);

	max_nl_size = (max_nl_size + CLUSTER_SIZE - 1) & CLUSTER_MASK;
	if (max_nl_cursor == 0)
		max_nl_cursor = CLUSTER_SIZE;

	/*遍历所有的非线性映射的vma, 清空最多max_nl_size个页表项???*/
	do {
		list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
			if (vma->vm_flags & (VM_LOCKED|VM_RESERVED))
				continue;
			cursor = (unsigned long) vma->vm_private_data;
			/*清空线性区vma从线性地址cursor~max_nl_cursor之间的页表项???*/
			while ( cursor < max_nl_cursor &&
				cursor < vma->vm_end - vma->vm_start) {
				/*从线性地址crusor开始扫描vma线性区CLUSTER_SIZE/PAGE_SIZE个线性地址所对应的页表项，并尝试将他们清0???*/
				try_to_unmap_cluster(cursor, &mapcount, vma);
				cursor += CLUSTER_SIZE;
				vma->vm_private_data = (void *) cursor;
				if ((int)mapcount <= 0)
					goto out;
			}
			vma->vm_private_data = (void *) max_nl_cursor;
		}
		cond_resched_lock(&mapping->i_mmap_lock);
		max_nl_cursor += CLUSTER_SIZE;
	} while (max_nl_cursor <= max_nl_size);

	/*
	 * Don't loop forever (perhaps all the remaining pages are
	 * in locked vmas).  Reset cursor on all unreserved nonlinear
	 * vmas, now forgetting on which ones it had fallen behind.
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
		if (!(vma->vm_flags & VM_RESERVED))
			vma->vm_private_data = NULL;
	}
out:
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 * Return values are:
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 */
/*清除所有引用页框page的页表项*/
int try_to_unmap(struct page *page)
{
	int ret;

	BUG_ON(!PageLocked(page));

	/*判断page是否为匿名页*/
	if (PageAnon(page))
		ret = try_to_unmap_anon(page);
	else
		ret = try_to_unmap_file(page);

	/*页框没有被任何页表项引用*/
	if (!page_mapped(page))
		ret = SWAP_SUCCESS;
	return ret;
}

