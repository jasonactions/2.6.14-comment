/*
 *	linux/mm/msync.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * The msync() system call.
 */
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/hugetlb.h>
#include <linux/syscalls.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static void msync_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end)
{
	pte_t *pte;
	spinlock_t *ptl;
	int progress = 0;

again:
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	do {
		unsigned long pfn;
		struct page *page;

		if (progress >= 64) {
			progress = 0;
			if (need_resched() || need_lockbreak(ptl))
				break;
		}
		progress++;
		if (!pte_present(*pte))
			continue;
		if (!pte_maybe_dirty(*pte))
			continue;
		pfn = pte_pfn(*pte);
		if (unlikely(!pfn_valid(pfn))) {
			print_bad_pte(vma, *pte, addr);
			continue;
		}
		page = pfn_to_page(pfn);

		if (ptep_clear_flush_dirty(vma, addr, pte) ||
		    page_test_and_clear_dirty(page))
			set_page_dirty(page);
		progress += 3;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();
	if (addr != end)
		goto again;
}

static inline void msync_pmd_range(struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		msync_pte_range(vma, pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void msync_pud_range(struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		msync_pmd_range(vma, pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static void msync_page_range(struct vm_area_struct *vma,
				unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	/* For hugepages we can't go walking the page table normally,
	 * but that's ok, hugetlbfs is memory based, so we don't need
	 * to do anything more on an msync().
	 * Can't do anything with VM_RESERVED regions either.
	 */
	if (vma->vm_flags & (VM_HUGETLB|VM_RESERVED))
		return;

	BUG_ON(addr >= end);
	pgd = pgd_offset(vma->vm_mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		msync_pud_range(vma, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

/*
 * MS_SYNC syncs the entire file - including mappings.
 *
 * MS_ASYNC does not start I/O (it used to, up to 2.5.67).  Instead, it just
 * marks the relevant pages dirty.  The application may now run fsync() to
 * write out the dirty pages and wait on the writeout and check the result.
 * Or the application may run fadvise(FADV_DONTNEED) against the fd to start
 * async writeout immediately.
 * So my _not_ starting I/O in MS_ASYNC we provide complete flexibility to
 * applications.
 */
static int msync_interval(struct vm_area_struct *vma,
			unsigned long addr, unsigned long end, int flags)
{
	int ret = 0;
	struct file *file = vma->vm_file;

	if ((flags & MS_INVALIDATE) && (vma->vm_flags & VM_LOCKED))
		return -EBUSY;
	
	/*线性区vma是file的可写共享区域*/
	if (file && (vma->vm_flags & VM_SHARED)) {
		msync_page_range(vma, addr, end);

		if (flags & MS_SYNC) {
			struct address_space *mapping = file->f_mapping;
			int err;
			
			/* start writeback against all of a mapping's dirty pages*/
			ret = filemap_fdatawrite(mapping);
			/*将文件在内存中所有修改的数据冲刷到磁盘，这个调用阻塞直到传输完成，它还冲刷和文件有关的元数据*/
			if (file->f_op && file->f_op->fsync) {
				/*
				 * We don't take i_sem here because mmap_sem
				 * is already held.
				 */
				err = file->f_op->fsync(file,file->f_dentry,1);
				if (err && !ret)
					ret = err;
			}
			/*等待address_space的所有page的PG_writeback标志清零,表示正在传输的IO结束*/
			err = filemap_fdatawait(mapping);
			if (!ret)
				ret = err;
		}
	}
	/*
	 * 运行到这里说明file为空或vma->vm_flags的VM_SHARED标志清零，
	 * 说明这个线性区不是文件的可写共享内存映射
	 */
	return ret;
}
/*
 * 把属于共享内存映射的脏页刷新到磁盘
 *
 * @start: 线性地址区间的起始地址
 * @len:区间的长度
 * @flags: MS_SYNC/MS_ASYNC/MS_INVALIDATE
 */
asmlinkage long sys_msync(unsigned long start, size_t len, int flags)
{
	unsigned long end;
	struct vm_area_struct *vma;
	int unmapped_error, error = -EINVAL;

	if (flags & MS_SYNC)
		current->flags |= PF_SYNCWRITE;

	down_read(&current->mm->mmap_sem);
	if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC))
		goto out;
	if (start & ~PAGE_MASK)
		goto out;
	/*标记MS_ASYSNC则返回*/
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		goto out;
	error = -ENOMEM;
	len = (len + ~PAGE_MASK) & PAGE_MASK;
	end = start + len;
	if (end < start)
		goto out;
	error = 0;
	if (end == start)
		goto out;
	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
	vma = find_vma(current->mm, start);
	unmapped_error = 0;
	/*遍历线性地址区间的每一个VMA*/
	for (;;) {
		/* Still start < end. */
		error = -ENOMEM;
		if (!vma)
			goto out;
		/* Here start < vma->vm_end. */
		if (start < vma->vm_start) {
			unmapped_error = -ENOMEM;
			start = vma->vm_start;
		}
		/* Here vma->vm_start <= start < vma->vm_end. */
		if (end <= vma->vm_end) {
			if (start < end) {
				/*将位于VMA中[start,ent]区间的page刷新到磁盘*/
				error = msync_interval(vma, start, end, flags);
				if (error)
					goto out;
			}
			error = unmapped_error;
			goto out;
		}
		/* Here vma->vm_start <= start < vma->vm_end < end. */
		error = msync_interval(vma, start, vma->vm_end, flags);
		if (error)
			goto out;
		start = vma->vm_end;
		vma = vma->vm_next;
	}
out:
	up_read(&current->mm->mmap_sem);
	current->flags &= ~PF_SYNCWRITE;
	return error;
}
