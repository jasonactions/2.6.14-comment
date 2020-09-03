/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include "filemap.h"
/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for generic_osync_inode */

#include <asm/uaccess.h>
#include <asm/mman.h>

static ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs);

/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_lock		(vmtruncate)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->mapping->tree_lock
 *
 *  ->i_sem
 *    ->i_mmap_lock		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_lock
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->mmap_sem
 *    ->i_sem			(msync)
 *
 *  ->i_sem
 *    ->i_alloc_sem             (various)
 *
 *  ->inode_lock
 *    ->sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_lock
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone.lru_lock		(follow_page->mark_page_accessed)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 *  ->task->proc_lock
 *    ->dcache_lock		(proc_pid_lookup)
 */

/*
 * Remove a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold a write_lock on the mapping's tree_lock.
 */
void __remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	radix_tree_delete(&mapping->page_tree, page->index);
	page->mapping = NULL;
	mapping->nrpages--;
	pagecache_acct(-1);
}

void remove_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;

	BUG_ON(!PageLocked(page));

	write_lock_irq(&mapping->tree_lock);
	__remove_from_page_cache(page);
	write_unlock_irq(&mapping->tree_lock);
}

static int sync_page(void *word)
{
	struct address_space *mapping;
	struct page *page;

	page = container_of((page_flags_t *)word, struct page, flags);

	/*
	 * page_mapping() is being called without PG_locked held.
	 * Some knowledge of the state and use of the page is used to
	 * reduce the requirements down to a memory barrier.
	 * The danger here is of a stale page_mapping() return value
	 * indicating a struct address_space different from the one it's
	 * associated with when it is associated with one.
	 * After smp_mb(), it's either the correct page_mapping() for
	 * the page, or an old page_mapping() and the page's own
	 * page_mapping() has gone NULL.
	 * The ->sync_page() address_space operation must tolerate
	 * page_mapping() going NULL. By an amazing coincidence,
	 * this comes about because none of the users of the page
	 * in the ->sync_page() methods make essential use of the
	 * page_mapping(), merely passing the page down to the backing
	 * device's unplug functions when it's non-NULL, which in turn
	 * ignore it for all cases but swap, where only page_private(page) is
	 * of interest. When page_mapping() does go NULL, the entire
	 * call stack gracefully ignores the page and returns.
	 * -- wli
	 */
	smp_mb();
	mapping = page_mapping(page);
	if (mapping && mapping->a_ops && mapping->a_ops->sync_page)
		mapping->a_ops->sync_page(page);
	io_schedule();
	return 0;
}

/**
 * filemap_fdatawrite_range - start writeback against all of a mapping's
 * dirty pages that lie within the byte offsets <start, end>
 * @mapping:	address space structure to write
 * @start:	offset in bytes where the range starts
 * @end:	offset in bytes where the range ends
 * @sync_mode:	enable synchronous operation
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory * cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 */
static int __filemap_fdatawrite_range(struct address_space *mapping,
	loff_t start, loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = mapping->nrpages * 2,
		.start = start,
		.end = end,
	};

	if (!mapping_cap_writeback_dirty(mapping))
		return 0;

	ret = do_writepages(mapping, &wbc);
	return ret;
}

/* start writeback against all of a mapping's dirty pages*/
static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, 0, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

static int filemap_fdatawrite_range(struct address_space *mapping,
	loff_t start, loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}

/*
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

/*
 * Wait for writeback to complete against pages indexed by start->end
 * inclusive
 */
static int wait_on_page_writeback_range(struct address_space *mapping,
				pgoff_t start, pgoff_t end)
{
	struct pagevec pvec;
	int nr_pages;
	int ret = 0;
	pgoff_t index;

	if (end < start)
		return 0;

	pagevec_init(&pvec, 0);
	index = start;
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			if (PageError(page))
				ret = -EIO;
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	/* Check for outstanding write errors */
	if (test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;

	return ret;
}

/*
 * Write and wait upon all the pages in the passed range.  This is a "data
 * integrity" operation.  It waits upon in-flight writeout before starting and
 * waiting upon new writeout.  If there was an IO error, return it.
 *
 * We need to re-take i_sem during the generic_osync_inode list walk because
 * it is otherwise livelockable.
 */
int sync_page_range(struct inode *inode, struct address_space *mapping,
			loff_t pos, size_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (!mapping_cap_writeback_dirty(mapping) || !count)
		return 0;
	/*将address_space中的page刷新到磁盘*/
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1);
	if (ret == 0) {
		down(&inode->i_sem);
		/*将索引节点和相关缓冲区刷新到磁盘*/
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA);
		up(&inode->i_sem);
	}
	if (ret == 0)
		/*等待全部所刷新的页面的PG_writeback标志清零*/
		ret = wait_on_page_writeback_range(mapping, start, end);
	return ret;
}
EXPORT_SYMBOL(sync_page_range);

/*
 * Note: Holding i_sem across sync_page_range_nolock is not a good idea
 * as it forces O_SYNC writers to different parts of the same file
 * to be serialised right until io completion.
 */
static int sync_page_range_nolock(struct inode *inode,
				  struct address_space *mapping,
				  loff_t pos, size_t count)
{
	pgoff_t start = pos >> PAGE_CACHE_SHIFT;
	pgoff_t end = (pos + count - 1) >> PAGE_CACHE_SHIFT;
	int ret;

	if (!mapping_cap_writeback_dirty(mapping) || !count)
		return 0;
	ret = filemap_fdatawrite_range(mapping, pos, pos + count - 1);
	if (ret == 0)
		ret = generic_osync_inode(inode, mapping, OSYNC_METADATA);
	if (ret == 0)
		ret = wait_on_page_writeback_range(mapping, start, end);
	return ret;
}

/**
 * filemap_fdatawait - walk the list of under-writeback pages of the given
 *     address space and wait for all of them.
 *
 * @mapping: address space structure to wait for
 */
int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return wait_on_page_writeback_range(mapping, 0,
				(i_size - 1) >> PAGE_CACHE_SHIFT);
}
EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int retval = 0;

	if (mapping->nrpages) {
		retval = filemap_fdatawrite(mapping);
		if (retval == 0)
			retval = filemap_fdatawait(mapping);
	}
	return retval;
}

int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int retval = 0;

	if (mapping->nrpages) {
		retval = __filemap_fdatawrite_range(mapping, lstart, lend,
						    WB_SYNC_ALL);
		if (retval == 0)
			retval = wait_on_page_writeback_range(mapping,
						    lstart >> PAGE_CACHE_SHIFT,
						    lend >> PAGE_CACHE_SHIFT);
	}
	return retval;
}

/*
 * This function is used to add newly allocated pagecache pages:
 * the page is new, so we can just run SetPageLocked() against it.
 * The other page state flags were set by rmqueue().
 *
 * This function does not add the page to the LRU.  The caller must do that.
 */
int add_to_page_cache(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	int error = radix_tree_preload(gfp_mask & ~__GFP_HIGHMEM);

	if (error == 0) {
		write_lock_irq(&mapping->tree_lock);
		error = radix_tree_insert(&mapping->page_tree, offset, page);
		if (!error) {
			page_cache_get(page);
			SetPageLocked(page);
			page->mapping = mapping;
			page->index = offset;
			mapping->nrpages++;
			pagecache_acct(1);
		}
		write_unlock_irq(&mapping->tree_lock);
		radix_tree_preload_end();
	}
	return error;
}

EXPORT_SYMBOL(add_to_page_cache);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	int ret = add_to_page_cache(page, mapping, offset, gfp_mask);
	if (ret == 0)
		lru_cache_add(page);
	return ret;
}

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
static wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}

static inline void wake_up_page(struct page *page, int bit)
{
	__wake_up_bit(page_waitqueue(page), &page->flags, bit);
}

void fastcall wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

/**
 * unlock_page() - unlock a locked page
 *
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechananism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * The first mb is necessary to safely close the critical section opened by the
 * TestSetPageLocked(), the second mb is necessary to enforce ordering between
 * the clear_bit and the read of the waitqueue (to avoid SMP races with a
 * parallel wait_on_page_locked()).
 */
void fastcall unlock_page(struct page *page)
{
	smp_mb__before_clear_bit();
	if (!TestClearPageLocked(page))
		BUG();
	smp_mb__after_clear_bit(); 
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

/*
 * End writeback against a page.
 */
void end_page_writeback(struct page *page)
{
	if (!TestClearPageReclaim(page) || rotate_reclaimable_page(page)) {
		if (!test_clear_page_writeback(page))
			BUG();
	}
	smp_mb__after_clear_bit();
	/*唤醒等待PG_writeback标志清零的所有进程*/
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/*
 * Get a lock on the page, assuming we need to sleep to get it.
 *
 * Ugly: running sync_page() in state TASK_UNINTERRUPTIBLE is scary.  If some
 * random driver's requestfn sets TASK_RUNNING, we could busywait.  However
 * chances are that on the second loop, the block layer's plug list is empty,
 * so sync_page() will then return in state TASK_UNINTERRUPTIBLE.
 */
void fastcall __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page), &wait, sync_page,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

/*
 * a rather lightweight function, finding and getting a reference to a
 * hashed page atomically.
 */
struct page * find_get_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	read_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page)
		page_cache_get(page);
	read_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_get_page);

/*
 * Same as above, but trylock it instead of incrementing the count.
 */
struct page *find_trylock_page(struct address_space *mapping, unsigned long offset)
{
	struct page *page;

	read_lock_irq(&mapping->tree_lock);
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page && TestSetPageLocked(page))
		page = NULL;
	read_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_trylock_page);

/**
 * find_lock_page - locate, pin and lock a pagecache page
 *
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Locates the desired pagecache page, locks it, increments its reference
 * count and returns its address.
 *
 * Returns zero if the page was not present. find_lock_page() may sleep.
 */
/*在cache中查找索引为offset的page，如果找到则lock page*/
struct page *find_lock_page(struct address_space *mapping,
				unsigned long offset)
{
	struct page *page;

	read_lock_irq(&mapping->tree_lock);
repeat:
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (page) {
		page_cache_get(page);
		if (TestSetPageLocked(page)) {
			read_unlock_irq(&mapping->tree_lock);
			lock_page(page);
			read_lock_irq(&mapping->tree_lock);

			/* Has the page been truncated while we slept? */
			if (page->mapping != mapping || page->index != offset) {
				unlock_page(page);
				page_cache_release(page);
				goto repeat;
			}
		}
	}
	read_unlock_irq(&mapping->tree_lock);
	return page;
}

EXPORT_SYMBOL(find_lock_page);

/**
 * find_or_create_page - locate or add a pagecache page
 *
 * @mapping: the page's address_space
 * @index: the page's index into the mapping
 * @gfp_mask: page allocation mode
 *
 * Locates a page in the pagecache.  If the page is not present, a new page
 * is allocated using @gfp_mask and is added to the pagecache and to the VM's
 * LRU list.  The returned page is locked and has its reference count
 * incremented.
 *
 * find_or_create_page() may sleep, even if @gfp_flags specifies an atomic
 * allocation!
 *
 * find_or_create_page() returns the desired page's address, or zero on
 * memory exhaustion.
 */
struct page *find_or_create_page(struct address_space *mapping,
		unsigned long index, gfp_t gfp_mask)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page = alloc_page(gfp_mask);
			if (!cached_page)
				return NULL;
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, gfp_mask);
		if (!err) {
			page = cached_page;
			cached_page = NULL;
		} else if (err == -EEXIST)
			goto repeat;
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

EXPORT_SYMBOL(find_or_create_page);

/**
 * find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * find_get_pages() returns the number of pages which were found.
 */
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	read_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup(&mapping->page_tree,
				(void **)pages, start, nr_pages);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	read_unlock_irq(&mapping->tree_lock);
	return ret;
}

/*
 * Like find_get_pages, except we only return pages which are tagged with
 * `tag'.   We update *index to index the next page for the traversal.
 */
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	unsigned int i;
	unsigned int ret;

	read_lock_irq(&mapping->tree_lock);
	ret = radix_tree_gang_lookup_tag(&mapping->page_tree,
				(void **)pages, *index, nr_pages, tag);
	for (i = 0; i < ret; i++)
		page_cache_get(pages[i]);
	if (ret)
		*index = pages[ret - 1]->index + 1;
	read_unlock_irq(&mapping->tree_lock);
	return ret;
}

/*
 * Same as grab_cache_page, but do not wait if the page is unavailable.
 * This is intended for speculative data generators, where the data can
 * be regenerated if the page couldn't be grabbed.  This routine should
 * be safe to call while holding the lock for another page.
 *
 * Clear __GFP_FS when allocating the page to avoid recursion into the fs
 * and deadlock against the caller's locked page.
 */
struct page *
grab_cache_page_nowait(struct address_space *mapping, unsigned long index)
{
	struct page *page = find_get_page(mapping, index);
	gfp_t gfp_mask;

	if (page) {
		if (!TestSetPageLocked(page))
			return page;
		page_cache_release(page);
		return NULL;
	}
	gfp_mask = mapping_gfp_mask(mapping) & ~__GFP_FS;
	page = alloc_pages(gfp_mask, 0);
	if (page && add_to_page_cache_lru(page, mapping, index, gfp_mask)) {
		page_cache_release(page);
		page = NULL;
	}
	return page;
}

EXPORT_SYMBOL(grab_cache_page_nowait);

/*
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level
 * stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 *
 * Note the struct file* is only passed for the use of readpage.  It may be
 * NULL.
 */
void do_generic_mapping_read(struct address_space *mapping,
			     struct file_ra_state *_ra,
			     struct file *filp,
			     loff_t *ppos,
			     read_descriptor_t *desc,
			     read_actor_t actor)
{
	/*
	 * 获取地址空间的的所有者即inode对象
	 * 对于普通文件它是filp->f_dentry->d_inode
	 * 对于块设备文件它是bdev->bd_inode 
	 */
	struct inode *inode = mapping->host;
	unsigned long index;
	unsigned long end_index;
	unsigned long offset;
	unsigned long last_index;
	unsigned long next_index;
	unsigned long prev_index;
	loff_t isize;
	struct page *cached_page;
	int error;
	struct file_ra_state ra = *_ra;

	cached_page = NULL;
	/*ppos对应的逻辑页索引*/
	index = *ppos >> PAGE_CACHE_SHIFT;
	next_index = index;
	prev_index = ra.prev_page;
	/*获取本次请求的最后一个字节所在的逻辑页索引*/
	last_index = (*ppos + desc->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	/*ppos对应的字节在逻辑页内的偏移*/
	offset = *ppos & ~PAGE_CACHE_MASK;

	/*获取文件长度*/
	isize = i_size_read(inode);
	if (!isize)
		goto out;
	
	/*将文件最后一个字节对齐到页*/
	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	for (;;) {
		struct page *page;
		unsigned long nr, ret;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			/*文件的最后一个字节所在逻辑页内的偏移量*/
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;

		cond_resched();
		/*当内核用用户态请求来读文件数据的页会触发此调用执行预读*/
		if (index == next_index)
			next_index = page_cache_readahead(mapping, &ra, filp,
					index, last_index - index);

find_page:
		page = find_get_page(mapping, index);
		if (unlikely(page == NULL)) {
			/*
			 * 通过上一步page_cache_readahead，请求页应该已经在page cache
			 * 如果没有，则说明被回收算法从高速缓存删除
			 * 因此调整预读系统参数来减少下次预读量
			 */
			handle_ra_miss(mapping, &ra, index);
			goto no_cached_page;
		}
		/*如果page已经在page cache中，但不是最新*/
		if (!PageUptodate(page))
			goto page_not_up_to_date;
page_ok:

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When (part of) the same page is read multiple times
		 * in succession, only mark it as accessed the first time.
		 */
		/*将页面的PG_referenced或PG_active置位，表示页正在被访问，不应该被置换出*/
		if (prev_index != index)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		/*实际读到的数据拷贝给用户缓冲区,其中会更新desc->count*/
		ret = actor(desc, page, offset, nr);
		offset += ret;
		/*更新index为读取后的page索引*/
		index += offset >> PAGE_CACHE_SHIFT;
		/*更新offset为最新的page页内偏移*/
		offset &= ~PAGE_CACHE_MASK;

		/*减少页描述符的引用计数*/
		page_cache_release(page);

		/*如果读描述符显示待读数据不为0则继续下一次循环读取*/
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		/*尝试锁定页面，如果其它进程正在读取，则会阻塞*/
		lock_page(page);

		/* Did it get unhashed before we got the lock? */
		/*为防止在持有锁后有进程将页面释放，检查page->mapping*/
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		/*
		 * 到此处可能已经有进程将数据从磁盘读取出放入page cache，则解锁页面
		 * 否则执行read_page从磁盘中读取
		 */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/* Start the actual read. The read will unlock the page. */
		/*read_page对普通文件一般被封装为mpage_readpage,如ext3*/
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error))
			goto readpage_error;

		if (!PageUptodate(page)) {
			/*
			 * 此处锁住页面，由于前面在find page时已经持有锁，因此此处会被阻塞
			 * 直到bio->end_io回调将页面标记为最新才会解锁
			 */
			lock_page(page);
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_inode_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		/*
		 * i_size must be checked after we have done ->readpage.
		 *
		 * Checking i_size after the readpage allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */
		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		/*
		 * 如果index超过文件包含的页数，将减少页的引用计数，并跳出
		 * 这种情况发生在当一个进程在读时，另一个进程在删减这个文件时
		 */
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		/*如果访问的是文件的最后一个字节所在的page*/
		if (index == end_index) {
			/*文件的最后一个字节所在page的偏移,也就是应被拷贝给用户的字节的大小*/
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;
		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		if (!cached_page) {
			/*申请一个新的page*/
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page) {
				desc->error = -ENOMEM;
				goto out;
			}
		}
		/*将page添加到高速缓存，并链入zone->inactive_lru链表,此函数会将PG_locked标志置位*/
		error = add_to_page_cache_lru(cached_page, mapping,
						index, GFP_KERNEL);
		if (error) {
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		page = cached_page;
		cached_page = NULL;
		goto readpage;
	}

out:
	/*所有请求的或可以读取到的数据已读完，更新预读数据*/
	*_ra = ra;
	
	/*把index*4096+offset赋值给ppos,供以后read/write调用*/
	*ppos = ((loff_t) index << PAGE_CACHE_SHIFT) + offset;
	if (cached_page)
		page_cache_release(cached_page);
	if (filp)
		file_accessed(filp);
}

EXPORT_SYMBOL(do_generic_mapping_read);

/*把page中的数据拷给用户缓冲区*/
int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page, KM_USER0);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr, KM_USER0);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	/*为处于高端内存中的页建立永久的内核映射*/
	kaddr = kmap(page);
	/*把页中数据拷贝给用户态地址空间*/
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	/*释放页的任一永久内核映射*/
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/*
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
/*
 * @iocb: 描述同步IO的操作状态
 * @iov: 描述待接收数据的用户缓冲区
 * @nr_segs：为iovec描述符数组的个数，被generic_file_read调用时只有1个元素
 * @ppos: 存放文件当前指针变量
 */
ssize_t
__generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t *ppos)
{
	/*获取跟当前io操作相关的file对象*/
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg;
	size_t count;

	count = 0;
	for (seg = 0; seg < nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		count += iv->iov_len;
		if (unlikely((ssize_t)(count|iv->iov_len) < 0))
			return -EINVAL;
		/*检查iovec描述的用户态缓冲区是否有效*/
		if (access_ok(VERIFY_WRITE, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		nr_segs = seg;
		count -= iv->iov_len;	/* This segment is no good */
		break;
	}

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (filp->f_flags & O_DIRECT) {
		loff_t pos = *ppos, size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		retval = 0;
		if (!count)
			goto out; /* skip atime */
		/*获取文件大小*/
		size = i_size_read(inode);
		if (pos < size) {
			retval = generic_file_direct_IO(READ, iocb,
						iov, pos, nr_segs);
			if (retval > 0 && !is_sync_kiocb(iocb))
				retval = -EIOCBQUEUED;
			if (retval > 0)
				*ppos = pos + retval;
		}
		file_accessed(filp);
		goto out;
	}

	retval = 0;
	if (count) {
		for (seg = 0; seg < nr_segs; seg++) {
			/*操作描述符，它存放与单个用户态缓冲相关的文件读操作的当前状态*/
			read_descriptor_t desc;

			desc.written = 0;
			desc.arg.buf = iov[seg].iov_base;
			desc.count = iov[seg].iov_len;
			if (desc.count == 0)
				continue;
			desc.error = 0;
			/*从磁盘读取数据到page，并拷贝给用户缓冲区，file_read_actor完成了page到用户缓冲区的拷贝*/
			do_generic_file_read(filp,ppos,&desc,file_read_actor);
			retval += desc.written;
			if (desc.error) {
				retval = retval ?: desc.error;
				break;
			}
		}
	}
out:
	return retval;
}

EXPORT_SYMBOL(__generic_file_aio_read);

ssize_t
generic_file_aio_read(struct kiocb *iocb, char __user *buf, size_t count, loff_t pos)
{
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };

	BUG_ON(iocb->ki_pos != pos);
	return __generic_file_aio_read(iocb, &local_iov, 1, &iocb->ki_pos);
}

EXPORT_SYMBOL(generic_file_aio_read);
/*
 * @ppos:一般为filp->f_pos
 * 实现了普通文件和块文件的通用read方法
 */
ssize_t
generic_file_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	struct iovec local_iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	ssize_t ret;

	/*初始化kiob描述符*/
	init_sync_kiocb(&kiocb, filp);
	ret = __generic_file_aio_read(&kiocb, &local_iov, 1, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}

EXPORT_SYMBOL(generic_file_read);

int file_send_actor(read_descriptor_t * desc, struct page *page, unsigned long offset, unsigned long size)
{
	ssize_t written;
	unsigned long count = desc->count;
	struct file *file = desc->arg.data;

	if (size > count)
		size = count;

	written = file->f_op->sendpage(file, page, offset,
				       size, &file->f_pos, size<count);
	if (written < 0) {
		desc->error = written;
		written = 0;
	}
	desc->count = count - written;
	desc->written += written;
	return written;
}

ssize_t generic_file_sendfile(struct file *in_file, loff_t *ppos,
			 size_t count, read_actor_t actor, void *target)
{
	read_descriptor_t desc;

	if (!count)
		return 0;

	desc.written = 0;
	desc.count = count;
	desc.arg.data = target;
	desc.error = 0;

	do_generic_file_read(in_file, ppos, &desc, actor);
	if (desc.written)
		return desc.written;
	return desc.error;
}

EXPORT_SYMBOL(generic_file_sendfile);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     unsigned long index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops || !mapping->a_ops->readpage)
		return -EINVAL;

	force_page_cache_readahead(mapping, filp, index,
					max_sane_readahead(nr));
	return 0;
}

asmlinkage ssize_t sys_readahead(int fd, loff_t offset, size_t count)
{
	ssize_t ret;
	struct file *file;

	ret = -EBADF;
	file = fget(fd);
	if (file) {
		if (file->f_mode & FMODE_READ) {
			struct address_space *mapping = file->f_mapping;
			unsigned long start = offset >> PAGE_CACHE_SHIFT;
			unsigned long end = (offset + count - 1) >> PAGE_CACHE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, file, start, len);
		}
		fput(file);
	}
	return ret;
}

#ifdef CONFIG_MMU
/*
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 */
static int FASTCALL(page_cache_read(struct file * file, unsigned long offset));
/*分配一个新的页框，追加到页高速缓存，通过readpage回调从磁盘读取数据到新的页框*/
static int fastcall page_cache_read(struct file * file, unsigned long offset)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page; 
	int error;

	page = page_cache_alloc_cold(mapping);
	if (!page)
		return -ENOMEM;

	error = add_to_page_cache_lru(page, mapping, offset, GFP_KERNEL);
	if (!error) {
		error = mapping->a_ops->readpage(file, page);
		page_cache_release(page);
		return error;
	}

	/*
	 * We arrive here in the unlikely event that someone 
	 * raced with us and added our page to the cache first
	 * or we are out of memory for radix-tree nodes.
	 */
	page_cache_release(page);
	return error == -EEXIST ? 0 : error;
}

#define MMAP_LOTSAMISS  (100)

/*
 * filemap_nopage() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 */
/*
 * 根据线性地址和线性区返回页面page，是nopiage方法的常见实现
 *
 * @area：所请求页所在线性区的描述符地址
 * @address：所请求页的线性地址
 * @type：存放函数侦测到的缺页类型（VM_FAULT_MAJOR或VM_FAULT_MINOR）
 */
struct page *filemap_nopage(struct vm_area_struct *area,
				unsigned long address, int *type)
{
	int error;
	struct file *file = area->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long size, pgoff;
	int did_readaround = 0, majmin = VM_FAULT_MINOR;

	/*pgoff存放address开始的页对应的数据在文件中的偏移量*/
	pgoff = ((address-area->vm_start) >> PAGE_CACHE_SHIFT) + area->vm_pgoff;

retry_all:
	/*size存放文件包含的页数*/
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (pgoff >= size)
		goto outside_data_content;

	/* If we don't want any read-ahead, don't bother */
	/*如果线性区VMA的VM_RAND_READ置位，假定进程以随机方式读内存映射中的页，忽略预读*/
	if (VM_RandomReadHint(area))
		goto no_cached_page;

	/*
	 * The readahead code wants to be told about each and every page
	 * so it can build and shrink its windows appropriately
	 *
	 * For sequential accesses, we use the generic readahead logic.
	 */
	/*如果线性区VMA的VM_SEQ_READ置位，假定进程以严格顺序方式读内存映射中的页*/
	if (VM_SequentialReadHint(area))
		/*从缺页处pgoff开始预读*/
		page_cache_readahead(mapping, ra, file, pgoff, 1);

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	page = find_get_page(mapping, pgoff);
	if (!page) {
		unsigned long ra_pages;
		
		/*预读算法失败，需要调整预读参数*/
		if (VM_SequentialReadHint(area)) {
			handle_ra_miss(mapping, ra, pgoff);
			goto no_cached_page;
		}
		ra->mmap_miss++;

		/*
		 * Do we miss much more than hit in this file? If so,
		 * stop bothering with read-ahead. It will only hurt.
		 */
		if (ra->mmap_miss > ra->mmap_hit + MMAP_LOTSAMISS)
			goto no_cached_page;

		/*
		 * To keep the pgmajfault counter straight, we need to
		 * check did_readaround, as this is an inner loop.
		 */
		if (!did_readaround) {
			majmin = VM_FAULT_MAJOR;
			inc_page_state(pgmajfault);
		}
		did_readaround = 1;
		/*如果预读没有被永久禁止（file_ra_state.ra_pages大于0,读取围绕请求页的一组页*/
		ra_pages = max_sane_readahead(file->f_ra.ra_pages);
		if (ra_pages) {
			pgoff_t start = 0;

			if (pgoff > ra_pages / 2)
				start = pgoff - ra_pages / 2;
			do_page_cache_readahead(mapping, file, start, ra_pages);
		}
		/*再次查询页是否已经在高速缓存中*/
		page = find_get_page(mapping, pgoff);
		if (!page)
			goto no_cached_page;
	}
	
	/*请求页已经在高速缓存mmap_hit加1*/
	if (!did_readaround)
		ra->mmap_hit++;

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	if (!PageUptodate(page))
		goto page_not_uptodate;

success:
	/*
	 * Found the page and have a reference on it.
	 */
	mark_page_accessed(page);
	if (type)
		/*设置页面类型*/
		*type = majmin;
	return page;

outside_data_content:
	/*
	 * An external ptracer can access pages that normally aren't
	 * accessible..
	 */
	if (area->vm_mm == current->mm)
		return NULL;
	/* Fall through to the non-read-ahead case */
no_cached_page:
	/*
	 * We're only likely to ever get here if MADV_RANDOM is in
	 * effect.
	 */
	/*分配一个新的页框，追加到页高速缓存，通过readpage回调从磁盘读取数据到新的页框*/
	error = page_cache_read(file, pgoff);
	/*尽可能为当前进程分配一个交换标记???*/
	grab_swap_token();

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	if (error == -ENOMEM)
		return NOPAGE_OOM;
	return NULL;

page_not_uptodate:
	if (!did_readaround) {
		majmin = VM_FAULT_MAJOR;
		inc_page_state(pgmajfault);
	}
	/*页面不是最新则锁定页面*/
	lock_page(page);

	/* Did it get unhashed while we waited for it? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry_all;
	}

	/* Did somebody else get it up-to-date? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}
	
	/*执行readpage回调从磁盘读取页面，然后等待页面解锁即是最新页面*/
	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry_all;
	}

	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}
	ClearPageError(page);
	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
	page_cache_release(page);
	return NULL;
}

EXPORT_SYMBOL(filemap_nopage);

static struct page * filemap_getpage(struct file *file, unsigned long pgoff,
					int nonblock)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page;
	int error;

	/*
	 * Do we have something in the page cache already?
	 */
retry_find:
	page = find_get_page(mapping, pgoff);
	if (!page) {
		if (nonblock)
			return NULL;
		goto no_cached_page;
	}

	/*
	 * Ok, found a page in the page cache, now we need to check
	 * that it's up-to-date.
	 */
	if (!PageUptodate(page)) {
		if (nonblock) {
			page_cache_release(page);
			return NULL;
		}
		goto page_not_uptodate;
	}

success:
	/*
	 * Found the page and have a reference on it.
	 */
	mark_page_accessed(page);
	return page;

no_cached_page:
	error = page_cache_read(file, pgoff);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	return NULL;

page_not_uptodate:
	lock_page(page);

	/* Did it get unhashed while we waited for it? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}

	/* Did somebody else get it up-to-date? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	lock_page(page);

	/* Somebody truncated the page on us? */
	if (!page->mapping) {
		unlock_page(page);
		goto err;
	}
	/* Somebody else successfully read it in? */
	if (PageUptodate(page)) {
		unlock_page(page);
		goto success;
	}

	ClearPageError(page);
	if (!mapping->a_ops->readpage(file, page)) {
		wait_on_page_locked(page);
		if (PageUptodate(page))
			goto success;
	}

	/*
	 * Things didn't work out. Return zero to tell the
	 * mm layer so, possibly freeing the page cache page first.
	 */
err:
	page_cache_release(page);

	return NULL;
}

/*对起始虚拟地址addr,长度为len，映射文件偏移为pgoff的一段映射区域进行重映射*/
int filemap_populate(struct vm_area_struct *vma, unsigned long addr,
		unsigned long len, pgprot_t prot, unsigned long pgoff,
		int nonblock)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned long size;
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	int err;

	/*预读映射文件的页*/
	if (!nonblock)
		force_page_cache_readahead(mapping, vma->vm_file,
					pgoff, len >> PAGE_CACHE_SHIFT);

repeat:
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (pgoff + (len >> PAGE_CACHE_SHIFT) > size)
		return -EINVAL;
	
	/*检查文件偏移为pgoff对应的page是否在高速缓存，如果不在则分配page并添加到高速缓存*/
	page = filemap_getpage(file, pgoff, nonblock);

	/* XXX: This is wrong, a filesystem I/O error may have happened. Fix that as
	 * done in shmem_populate calling shmem_getpage */
	if (!page && !nonblock)
		return -ENOMEM;

	if (page) {
		/*更新虚拟地址addr对应的页表项*/
		err = install_page(mm, vma, addr, page, prot);
		if (err) {
			page_cache_release(page);
			return err;
		}
	} else if (vma->vm_flags & VM_NONLINEAR) {
		/* No page was found just because we can't read it in now (being
		 * here implies nonblock != 0), but the page may exist, so set
		 * the PTE to fault it in later. */
		/* 
		 * 更新虚拟地址addr对应的页表项,将pte页表项的Present位清0，Dirty位置位，
		 * 等待触发page fault时由handle_pte_fault处理
		 */
		err = install_file_pte(mm, vma, addr, pgoff, prot);
		if (err)
			return err;
	}

	len -= PAGE_SIZE;
	addr += PAGE_SIZE;
	pgoff++;
	if (len)
		goto repeat;

	return 0;
}
EXPORT_SYMBOL(filemap_populate);

struct vm_operations_struct generic_file_vm_ops = {
	.nopage		= filemap_nopage,
	.populate	= filemap_populate,
};

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

/*
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static inline struct page *__read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page, *cached_page = NULL;
	int err;
repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		if (!cached_page) {
			cached_page = page_cache_alloc_cold(mapping);
			if (!cached_page)
				return ERR_PTR(-ENOMEM);
		}
		err = add_to_page_cache_lru(cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err < 0) {
			/* Presumably ENOMEM for radix tree node */
			page_cache_release(cached_page);
			return ERR_PTR(err);
		}
		page = cached_page;
		cached_page = NULL;
		err = filler(data, page);
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		}
	}
	if (cached_page)
		page_cache_release(cached_page);
	return page;
}

/*
 * Read into the page cache. If a page already exists,
 * and PageUptodate() is not set, try to fill the page.
 */
struct page *read_cache_page(struct address_space *mapping,
				unsigned long index,
				int (*filler)(void *,struct page*),
				void *data)
{
	struct page *page;
	int err;

retry:
	page = __read_cache_page(mapping, index, filler, data);
	if (IS_ERR(page))
		goto out;
	mark_page_accessed(page);
	if (PageUptodate(page))
		goto out;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page);
	if (err < 0) {
		page_cache_release(page);
		page = ERR_PTR(err);
	}
 out:
	return page;
}

EXPORT_SYMBOL(read_cache_page);

/*
 * If the page was newly created, increment its refcount and add it to the
 * caller's lru-buffering pagevec.  This function is specifically for
 * generic_file_write().
 */
/*在address_space查找索引为index的page*/
static inline struct page *
__grab_cache_page(struct address_space *mapping, unsigned long index,
			struct page **cached_page, struct pagevec *lru_pvec)
{
	int err;
	struct page *page;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		if (!*cached_page) {
			*cached_page = page_cache_alloc(mapping);
			if (!*cached_page)
				return NULL;
		}
		err = add_to_page_cache(*cached_page, mapping,
					index, GFP_KERNEL);
		if (err == -EEXIST)
			goto repeat;
		if (err == 0) {
			page = *cached_page;
			page_cache_get(page);
			if (!pagevec_add(lru_pvec, page))
				__pagevec_lru_add(lru_pvec);
			*cached_page = NULL;
		}
	}
	return page;
}

/*
 * The logic we want is
 *
 *	if suid or (sgid and xgrp)
 *		remove privs
 */
int remove_suid(struct dentry *dentry)
{
	mode_t mode = dentry->d_inode->i_mode;
	int kill = 0;
	int result = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && !capable(CAP_FSETID))) {
		struct iattr newattrs;

		newattrs.ia_valid = ATTR_FORCE | kill;
		result = notify_change(dentry, &newattrs);
	}
	return result;
}
EXPORT_SYMBOL(remove_suid);

size_t
__filemap_copy_from_user_iovec(char *vaddr, 
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left)) {
			/* zero the rest of the target like __copy_from_user */
			if (bytes)
				memset(vaddr, 0, bytes);
			break;
		}
	}
	return copied - left;
}

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position aor amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
/*对文件大小进行一些检查*/
inline int generic_write_checks(struct file *file, loff_t *pos, size_t *count, int isblk)
{
	struct inode *inode = file->f_mapping->host;
	/*每用户文件上限*/
	unsigned long limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;

        if (unlikely(*pos < 0))
                return -EINVAL;
	
	/*如果是普通文件*/
	if (!isblk) {
		/* FIXME: this is for backwards compatibility with 2.4 */
		if (file->f_flags & O_APPEND)
			/*修改文件尾标记*/
                        *pos = i_size_read(inode);

		if (limit != RLIM_INFINITY) {
			/*如果文件大小超过用户上限*/
			if (*pos >= limit) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			if (*count > limit - (typeof(limit))*pos) {
				*count = limit - (typeof(limit))*pos;
			}
		}
	}

	/*
	 * LFS rule
	 */
	if (unlikely(*pos + *count > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (*pos >= MAX_NON_LFS) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
		if (*count > MAX_NON_LFS - (unsigned long)*pos) {
			*count = MAX_NON_LFS - (unsigned long)*pos;
		}
	}

	/*
	 * Are we about to exceed the fs block limit ?
	 *
	 * If we have written data it becomes a short write.  If we have
	 * exceeded without writing data we send a signal and return EFBIG.
	 * Linus frestrict idea will clean these up nicely..
	 */
	if (likely(!isblk)) {
		/*如果文件大小超过文件系统上限*/
		if (unlikely(*pos >= inode->i_sb->s_maxbytes)) {
			if (*count || *pos > inode->i_sb->s_maxbytes) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			/* zero-length writes at ->s_maxbytes are OK */
		}

		if (unlikely(*pos + *count > inode->i_sb->s_maxbytes))
			*count = inode->i_sb->s_maxbytes - *pos;
	} else {
		loff_t isize;
		if (bdev_read_only(I_BDEV(inode)))
			return -EPERM;
		isize = i_size_read(inode);
		if (*pos >= isize) {
			if (*count || *pos > isize)
				return -ENOSPC;
		}

		if (*pos + *count > isize)
			*count = isize - *pos;
	}
	return 0;
}
EXPORT_SYMBOL(generic_write_checks);

ssize_t
generic_file_direct_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long *nr_segs, loff_t pos, loff_t *ppos,
		size_t count, size_t ocount)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t		written;

	if (count != ocount)
		*nr_segs = iov_shorten((struct iovec *)iov, *nr_segs, count);

	written = generic_file_direct_IO(WRITE, iocb, iov, pos, *nr_segs);
	if (written > 0) {
		loff_t end = pos + written;
		if (end > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode,  end);
			mark_inode_dirty(inode);
		}
		*ppos = end;
	}

	/*
	 * Sync the fs metadata but not the minor inode changes and
	 * of course not the data as we did direct DMA for the IO.
	 * i_sem is held, which protects generic_osync_inode() from
	 * livelocking.
	 */
	if (written >= 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err = generic_osync_inode(inode, mapping, OSYNC_METADATA);
		if (err < 0)
			written = err;
	}
	if (written == count && !is_sync_kiocb(iocb))
		written = -EIOCBQUEUED;
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write);
/*
 * @iocb: 用于跟踪当前正在进行的IO操作
 * @pos: 经过调整后的写入位置
 * @ppos: 原来的未调整的写入位置
 * @count: 要写入的字节数
 * @written：已经写入的字节数
 */
ssize_t
generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos, loff_t *ppos,
		size_t count, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct address_space_operations *a_ops = mapping->a_ops;
	struct inode 	*inode = mapping->host;
	long		status = 0;
	struct page	*page;
	struct page	*cached_page = NULL;
	size_t		bytes;
	struct pagevec	lru_pvec;
	const struct iovec *cur_iov = iov; /* current iovec */
	size_t		iov_base = 0;	   /* offset in the current iovec */
	char __user	*buf;

	pagevec_init(&lru_pvec, 0);

	/*
	 * handle partial DIO write.  Adjust cur_iov if needed.
	 */
	if (likely(nr_segs == 1))
		buf = iov->iov_base + written;
	else {
		filemap_set_next_iovec(&cur_iov, &iov_base, written);
		buf = cur_iov->iov_base + iov_base;
	}

	do {
		unsigned long index;
		unsigned long offset;
		unsigned long maxlen;
		size_t copied;
		
		/*获取写入位置所在page的偏移*/
		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		/*获取写入位置所在的page索引*/
		index = pos >> PAGE_CACHE_SHIFT;
		/*获取写入位置所在的页从写入位置到页尾的字节*/
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 */
		maxlen = cur_iov->iov_len - iov_base;
		if (maxlen > bytes)
			maxlen = bytes;
		/*??*/
		fault_in_pages_readable(buf, maxlen);

		/*获取一个page并添加到lru_pvec中,期间会增加page的引用计数值，并设置PG_locked标记*/
		page = __grab_cache_page(mapping,index,&cached_page,&lru_pvec);
		if (!page) {
			status = -ENOMEM;
			break;
		}
		/*调用prepare_write回调为该页分配并初始化buffer_head*/
		status = a_ops->prepare_write(file, page, offset, offset+bytes);
		if (unlikely(status)) {
			loff_t isize = i_size_read(inode);
			/*
			 * prepare_write() may have instantiated a few blocks
			 * outside i_size.  Trim these off again.
			 */
			unlock_page(page);
			page_cache_release(page);
			if (pos + bytes > isize)
				vmtruncate(inode, isize);
			break;
		}
		if (likely(nr_segs == 1))
			/*将用户空间数据拷贝到page*/
			copied = filemap_copy_from_user(page, offset,
							buf, bytes);
		else
			copied = filemap_copy_from_user_iovec(page, offset,
						cur_iov, iov_base, bytes);
		flush_dcache_page(page);
		/*将缓冲区标记为脏，以便随后把它们写入磁盘*/
		status = a_ops->commit_write(file, page, offset, offset+bytes);
		if (likely(copied > 0)) {
			if (!status)
				status = copied;

			if (status >= 0) {
				/*更新written, count, pos等*/
				written += status;
				count -= status;
				pos += status;
				buf += status;
				if (unlikely(nr_segs > 1)) {
					filemap_set_next_iovec(&cur_iov,
							&iov_base, status);
					if (count)
						buf = cur_iov->iov_base +
							iov_base;
				} else {
					iov_base += status;
				}
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		/*清PG_locked标志，唤醒等待该页的任何进程*/
		unlock_page(page);
		/*为回收算法更新页状态*/
		mark_page_accessed(page);
		/*减少页的引用计数值*/
		page_cache_release(page);
		if (status < 0)
			break;
		/*检查page/buffer cache中脏页比例是否超过一个固定的阀值（通常为系统页40%）,如果是就刷新页到磁盘*/
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	} while (count);
	/*写操作文件的所有页都已经处理，更新ppos让它指向文件的最后一个字符*/
	*ppos = pos;

	if (cached_page)
		page_cache_release(cached_page);

	/*
	 * For now, when the user asks for O_SYNC, we'll actually give O_DSYNC
	 */
	if (likely(status >= 0)) {
		if (unlikely((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
			if (!a_ops->writepage || !is_sync_kiocb(iocb))
				status = generic_osync_inode(inode, mapping,
						OSYNC_METADATA|OSYNC_DATA);
		}
  	}
	
	/*
	 * If we get here for O_DIRECT writes then we must have fallen through
	 * to buffered writes (block instantiation inside i_size).  So we sync
	 * the file data here, to try to honour O_DIRECT expectations.
	 */
	if (unlikely(file->f_flags & O_DIRECT) && written)
		status = filemap_write_and_wait(mapping);

	pagevec_lru_add(&lru_pvec);
	/*返回写入文件的字符*/
	return written ? written : status;
}
EXPORT_SYMBOL(generic_file_buffered_write);
/*
 * @iov: 
 * @nr_segs:iov数组的长度,generic_file_write只有一个元素
 */
static ssize_t
__generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	/*存放要写入的字节长度*/
	size_t ocount;		/* original count */
	/*存放经过检查后合法的要写入的字节长度*/
	size_t count;		/* after file limit checks */
	struct inode 	*inode = mapping->host;
	unsigned long	seg;
	loff_t		pos;
	/*存放已经写入的字节数*/
	ssize_t		written;
	ssize_t		err;

	ocount = 0;
	/*遍历各段iovec，对其进行检查，如果有不合法的iovec则退出循环*/
	for (seg = 0; seg < nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		ocount += iv->iov_len;
		if (unlikely((ssize_t)(ocount|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(VERIFY_READ, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		nr_segs = seg;
		ocount -= iv->iov_len;	/* This segment is no good */
		break;
	}

	count = ocount;
	pos = *ppos;

	vfs_check_frozen(inode->i_sb, SB_FREEZE_WRITE);

	/* We can write back this queue in page reclaim */
	/*即使相应请求队列是拥塞的，此设置也会允许当前进程写回由file->f_mapping拥有的脏页??*/
	current->backing_dev_info = mapping->backing_dev_info;
	written = 0;
	
	/* 对文件大小进行检查 */
	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;

	/*将suid标记清零,进程不能获取文件拥有者的ID*/
	err = remove_suid(file->f_dentry);
	if (err)
		goto out;

	/*update mtime and ctime time*/
	inode_update_time(inode, 1);

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (unlikely(file->f_flags & O_DIRECT)) {
		written = generic_file_direct_write(iocb, iov,
				&nr_segs, pos, ppos, count, ocount);
		if (written < 0 || written == count)
			goto out;
		/*
		 * direct-io write to a hole: fall through to buffered I/O
		 * for completing the rest of the request.
		 */
		pos += written;
		count -= written;
	}

	written = generic_file_buffered_write(iocb, iov, nr_segs,
			pos, ppos, count, written);
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(generic_file_aio_write_nolock);

ssize_t
generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	loff_t pos = *ppos;

	ret = __generic_file_aio_write_nolock(iocb, iov, nr_segs, ppos);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range_nolock(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
/*
 * @iov: 保存了用户空间地址和长度
 * @nr_segs:
 * @ppos:要写入文件的位置
 */
static ssize_t
__generic_file_write_nolock(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;
	/*初始化为kiocb.ki_key=KIOCB_SYNC_KEY; kiocb.ki_obj.tsk=current;kiocb->ki_filp=file*/
	init_sync_kiocb(&kiocb, file);
	ret = __generic_file_aio_write_nolock(&kiocb, iov, nr_segs, ppos);
	if (ret == -EIOCBQUEUED)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}

ssize_t
generic_file_write_nolock(struct file *file, const struct iovec *iov,
				unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	ret = generic_file_aio_write_nolock(&kiocb, iov, nr_segs, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}
EXPORT_SYMBOL(generic_file_write_nolock);

ssize_t generic_file_aio_write(struct kiocb *iocb, const char __user *buf,
			       size_t count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };

	BUG_ON(iocb->ki_pos != pos);

	down(&inode->i_sem);
	ret = __generic_file_aio_write_nolock(iocb, &local_iov, 1,
						&iocb->ki_pos);
	up(&inode->i_sem);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;

		err = sync_page_range(inode, mapping, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_aio_write);

/*通用的文件写函数*/
ssize_t generic_file_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t	ret;
	struct iovec local_iov = { .iov_base = (void __user *)buf,
					.iov_len = count };
	/*一次只能有一个进程发出write系统调用*/
	down(&inode->i_sem);
	ret = __generic_file_write_nolock(file, &local_iov, 1, ppos);
	up(&inode->i_sem);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		ssize_t err;
		/*将__generic_file_write_nolock涉及的所有页刷新到磁盘,阻塞当前进程，直到IO数据传送结束*/
		err = sync_page_range(inode, mapping, *ppos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_write);

ssize_t generic_file_readv(struct file *filp, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	ret = __generic_file_aio_read(&kiocb, iov, nr_segs, ppos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	return ret;
}
EXPORT_SYMBOL(generic_file_readv);

ssize_t generic_file_writev(struct file *file, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;

	down(&inode->i_sem);
	ret = __generic_file_write_nolock(file, iov, nr_segs, ppos);
	up(&inode->i_sem);

	if (ret > 0 && ((file->f_flags & O_SYNC) || IS_SYNC(inode))) {
		int err;

		err = sync_page_range(inode, mapping, *ppos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_writev);

/*
 * Called under i_sem for writes to S_ISREG files.   Returns -EIO if something
 * went wrong during pagecache shootdown.
 */
/*
 * @rw: READ/WRITE
 * @iocb：kiocb描述符指针
 * @iov: iovec描述符数组指针
 * @nr_segs:iov数组中iovec描述符数
 */
static ssize_t
generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
	loff_t offset, unsigned long nr_segs)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t retval;
	size_t write_len = 0;

	/*
	 * If it's a write, unmap all mmappings of the file up-front.  This
	 * will cause any pte dirty bits to be propagated into the pageframes
	 * for the subsequent filemap_write_and_wait().
	 */
	/*
	 * 如果操作类型为WRITE，而且一个或多个进程已经创建了与文件的某个部分关联的内存映射
	 * 则通过unmap_mapping_range取消该文件所有页的内存映射
	 * 如何任何取消的映射的页所对应的页表项，其Dirty位置位，
	 * 则该函数也确保它在页高速缓存的相应页标记为脏
	 */
	if (rw == WRITE) {
		write_len = iov_length(iov, nr_segs);
	       	if (mapping_mapped(mapping))
			unmap_mapping_range(mapping, offset, write_len, 0);
	}
	
	/*
	 * 刷新所有的脏页到磁盘,并等待I/O结束结束
	 * 当前进程采用DIRECT IO，但是其它进程也可能会采用非direct io方式访问，
	 * 因此高速缓存还可能有磁盘文件对应的缓存page，需要将缓存page与磁盘同步
	 */
	retval = filemap_write_and_wait(mapping);
	if (retval == 0) {
		/*一般为__blockdev_direct_IO函数的封装,通常IO传送完毕之后才返回*/
		retval = mapping->a_ops->direct_IO(rw, iocb, iov,
						offset, nr_segs);
		if (rw == WRITE && mapping->nrpages) {
			pgoff_t end = (offset + write_len - 1)
						>> PAGE_CACHE_SHIFT;
			/*扫描mapping基树中的所有页并释放它们,同时也清空指向这些页的用户态页表项*/
			int err = invalidate_inode_pages2_range(mapping,
					offset >> PAGE_CACHE_SHIFT, end);
			if (err)
				retval = err;
		}
	}
	return retval;
}
