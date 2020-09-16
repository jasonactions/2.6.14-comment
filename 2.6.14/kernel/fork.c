/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also entry.S and others).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/smp_lock.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/namespace.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/acct.h>

#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/*
 * Protected counters by write_lock_irq(&tasklist_lock)
 */
unsigned long total_forks;	/* Handle normal Linux uptimes. */
int nr_threads; 		/* The idle threads do not count.. */

/*系统所允许的最大进程数，总的原则是thread_info描述符和内核栈所占空间不超过物理内存的1/8*/
int max_threads;		/* tunable limit on nr_threads */

DEFINE_PER_CPU(unsigned long, process_counts) = 0;

 __cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */

EXPORT_SYMBOL(tasklist_lock);

int nr_processes(void)
{
	int cpu;
	int total = 0;

	for_each_online_cpu(cpu)
		total += per_cpu(process_counts, cpu);

	return total;
}

#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
# define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
# define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
static kmem_cache_t *task_struct_cachep;
#endif

/* SLAB cache for signal_struct structures (tsk->signal) */
kmem_cache_t *signal_cachep;

/* SLAB cache for sighand_struct structures (tsk->sighand) */
kmem_cache_t *sighand_cachep;

/* SLAB cache for files_struct structures (tsk->files) */
kmem_cache_t *files_cachep;

/* SLAB cache for fs_struct structures (tsk->fs) */
kmem_cache_t *fs_cachep;

/* SLAB cache for vm_area_struct structures */
kmem_cache_t *vm_area_cachep;

/* SLAB cache for mm_struct structures (tsk->mm) */
static kmem_cache_t *mm_cachep;

void free_task(struct task_struct *tsk)
{
	free_thread_info(tsk->thread_info);
	free_task_struct(tsk);
}
EXPORT_SYMBOL(free_task);

void __put_task_struct(struct task_struct *tsk)
{
	WARN_ON(!(tsk->exit_state & (EXIT_DEAD | EXIT_ZOMBIE)));
	WARN_ON(atomic_read(&tsk->usage));
	WARN_ON(tsk == current);

	if (unlikely(tsk->audit_context))
		audit_free(tsk);
	security_task_free(tsk);
	free_uid(tsk->user);
	put_group_info(tsk->group_info);

	if (!profile_handoff_task(tsk))
		free_task(tsk);
}

void __init fork_init(unsigned long mempages)
{
#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
#ifndef ARCH_MIN_TASKALIGN
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES
#endif
	/* create a slab on which task_structs can be allocated */
	task_struct_cachep =
		kmem_cache_create("task_struct", sizeof(struct task_struct),
			ARCH_MIN_TASKALIGN, SLAB_PANIC, NULL, NULL);
#endif

	/*
	 * The default maximum number of threads is set to a safe
	 * value: the thread structures can take up at most half
	 * of memory.
	 */
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);

	/*
	 * we need to allow at least 20 threads to boot a system
	 */
	if(max_threads < 20)
		max_threads = 20;

	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
	init_task.signal->rlim[RLIMIT_SIGPENDING] =
		init_task.signal->rlim[RLIMIT_NPROC];
}

static struct task_struct *dup_task_struct(struct task_struct *orig)
{
	struct task_struct *tsk;
	struct thread_info *ti;

	/*把FPU, MMX和SSE/SSE2寄存器的内容保存到父进程的thread_info结构中*/
	prepare_to_copy(orig);

	/*为新进程分配进程描述符*/
	tsk = alloc_task_struct();
	if (!tsk)
		return NULL;

	/*为新进程分配thread_info和内核栈*/
	ti = alloc_thread_info(tsk);
	if (!ti) {
		free_task_struct(tsk);
		return NULL;
	}

	/*将父进程的thread_info拷贝给子进程的thread_info*/
	*ti = *orig->thread_info;
	/*将父进程的进程描述符拷贝给子进程*/
	*tsk = *orig;
	tsk->thread_info = ti;
	ti->task = tsk;

	/* One for us, one for whoever does the "release_task()" (usually parent) */
	/*设置进程描述符使用计数器，表示进程描述符被使用，为何是2???*/
	atomic_set(&tsk->usage,2);
	atomic_set(&tsk->fs_excl, 0);
	return tsk;
}

#ifdef CONFIG_MMU
/*拷贝线性区和页表，对于私有的、可写的页所对应的页框，标记为对父子进程是只读的*/
static inline int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;
	struct mempolicy *pol;

	down_write(&oldmm->mmap_sem);
	flush_cache_mm(oldmm);
	down_write(&mm->mmap_sem);

	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->free_area_cache = oldmm->mmap_base;
	mm->cached_hole_size = ~0UL;
	mm->map_count = 0;
	cpus_clear(mm->cpu_vm_mask);
	mm->mm_rb = RB_ROOT;
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;

	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct file *file;

		/*如果线性区标记为创建新进程时不拷贝*/
		if (mpnt->vm_flags & VM_DONTCOPY) {
			long pages = vma_pages(mpnt);
			mm->total_vm -= pages;
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,
								-pages);
			continue;
		}
		charge = 0;
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned int len = (mpnt->vm_end - mpnt->vm_start) >> PAGE_SHIFT;
			if (security_vm_enough_memory(len))
				goto fail_nomem;
			charge = len;
		}
		tmp = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		pol = mpol_copy(vma_policy(mpnt));
		retval = PTR_ERR(pol);
		if (IS_ERR(pol))
			goto fail_nomem_policy;
		vma_set_policy(tmp, pol);
		tmp->vm_flags &= ~VM_LOCKED;
		tmp->vm_mm = mm;
		tmp->vm_next = NULL;
		anon_vma_link(tmp);
		file = tmp->vm_file;
		if (file) {
			struct inode *inode = file->f_dentry->d_inode;
			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);
      
			/* insert tmp into the share list, just after mpnt */
			spin_lock(&file->f_mapping->i_mmap_lock);
			tmp->vm_truncate_count = mpnt->vm_truncate_count;
			flush_dcache_mmap_lock(file->f_mapping);
			vma_prio_tree_add(tmp, mpnt);
			flush_dcache_mmap_unlock(file->f_mapping);
			spin_unlock(&file->f_mapping->i_mmap_lock);
		}

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		/*拷贝页表,tmp为子进程的vma*/
		retval = copy_page_range(mm, oldmm, tmp);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	retval = 0;
out:
	up_write(&mm->mmap_sem);
	flush_tlb_mm(oldmm);
	up_write(&oldmm->mmap_sem);
	return retval;
fail_nomem_policy:
	kmem_cache_free(vm_area_cachep, tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto out;
}

/*创建进程的pgd,pmd，pte将在dup_mmap创建*/
static inline int mm_alloc_pgd(struct mm_struct * mm)
{
	mm->pgd = pgd_alloc(mm);
	if (unlikely(!mm->pgd))
		return -ENOMEM;
	return 0;
}

static inline void mm_free_pgd(struct mm_struct * mm)
{
	pgd_free(mm->pgd);
}
#else
#define dup_mmap(mm, oldmm)	(0)
#define mm_alloc_pgd(mm)	(0)
#define mm_free_pgd(mm)
#endif /* CONFIG_MMU */

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);

#define allocate_mm()	(kmem_cache_alloc(mm_cachep, SLAB_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))

#include <linux/init_task.h>

 /*初始化一个内存描述符*/
static struct mm_struct * mm_init(struct mm_struct * mm)
{
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	init_rwsem(&mm->mmap_sem);
	INIT_LIST_HEAD(&mm->mmlist);
	mm->core_waiters = 0;
	mm->nr_ptes = 0;
	set_mm_counter(mm, file_rss, 0);
	set_mm_counter(mm, anon_rss, 0);
	spin_lock_init(&mm->page_table_lock);
	rwlock_init(&mm->ioctx_list_lock);
	mm->ioctx_list = NULL;
	mm->default_kioctx = (struct kioctx)INIT_KIOCTX(mm->default_kioctx, *mm);
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	mm->cached_hole_size = ~0UL;
	
	/*为新进程创建全新的pgd页表*/
	if (likely(!mm_alloc_pgd(mm))) {
		mm->def_flags = 0;
		return mm;
	}
	free_mm(mm);
	return NULL;
}

/*
 * Allocate and initialize an mm_struct.
 */
/*分配一个内存描述符*/
struct mm_struct * mm_alloc(void)
{
	struct mm_struct * mm;

	mm = allocate_mm();
	if (mm) {
		memset(mm, 0, sizeof(*mm));
		mm = mm_init(mm);
	}
	return mm;
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void fastcall __mmdrop(struct mm_struct *mm)
{
	BUG_ON(mm == &init_mm);
	mm_free_pgd(mm);
	destroy_context(mm);
	free_mm(mm);
}

/*
 * Decrement the use count and release all resources for an mm.
 */
/*释放mm_struct内存描述符*/
void mmput(struct mm_struct *mm)
{
	if (atomic_dec_and_test(&mm->mm_users)) {
		exit_aio(mm);
		/*释放局部描述符表?? 线性区描述符及内存描述符所引用的页表*/`
		exit_mmap(mm);
		if (!list_empty(&mm->mmlist)) {
			spin_lock(&mmlist_lock);
			list_del(&mm->mmlist);
			spin_unlock(&mmlist_lock);
		}
		/*释放mm的swap token*/
		put_swap_token(mm);
		/*递减mm_count,如果为0则释放mm_struct*/
		mmdrop(mm);
	}
}
EXPORT_SYMBOL_GPL(mmput);

/**
 * get_task_mm - acquire a reference to the task's mm
 *
 * Returns %NULL if the task has no mm.  Checks PF_BORROWED_MM (meaning
 * this kernel workthread has transiently adopted a user mm with use_mm,
 * to do its AIO) is not set and if so returns a reference to it, after
 * bumping up the use count.  User must release the mm via mmput()
 * after use.  Typically used by /proc and ptrace.
 */
struct mm_struct *get_task_mm(struct task_struct *task)
{
	struct mm_struct *mm;

	task_lock(task);
	mm = task->mm;
	if (mm) {
		if (task->flags & PF_BORROWED_MM)
			mm = NULL;
		else
			atomic_inc(&mm->mm_users);
	}
	task_unlock(task);
	return mm;
}
EXPORT_SYMBOL_GPL(get_task_mm);

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	struct completion *vfork_done = tsk->vfork_done;

	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);

	/* notify parent sleeping on vfork() */
	if (vfork_done) {
		tsk->vfork_done = NULL;
		complete(vfork_done);
	}
	if (tsk->clear_child_tid && atomic_read(&mm->mm_users) > 1) {
		u32 __user * tidptr = tsk->clear_child_tid;
		tsk->clear_child_tid = NULL;

		/*
		 * We don't check the error code - if userspace has
		 * not set up a proper pointer then tough luck.
		 */
		put_user(0, tidptr);
		sys_futex(tidptr, FUTEX_WAKE, 1, NULL, NULL, 0);
	}
}

/*通过建立新进程的所有页表和内存描述符来创建进程的地址空间*/
static int copy_mm(unsigned long clone_flags, struct task_struct * tsk)
{
	struct mm_struct * mm, *oldmm;
	int retval;

	tsk->min_flt = tsk->maj_flt = 0;
	tsk->nvcsw = tsk->nivcsw = 0;

	tsk->mm = NULL;
	tsk->active_mm = NULL;

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	oldmm = current->mm;
	if (!oldmm)
		return 0;

	/*如果设置了CLONE_VM标志则不需要拷贝内存描述符,线性区，页表*/
	if (clone_flags & CLONE_VM) {
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		/*
		 * There are cases where the PTL is held to ensure no
		 * new threads start up in user mode using an mm, which
		 * allows optimizing out ipis; the tlb_gather_mmu code
		 * is an example.
		 */
		/*此处自旋锁除了保护页表，还禁止创建轻量级进程，因为current->mm是共享的临界资源*/
		spin_unlock_wait(&oldmm->page_table_lock);
		goto good_mm;
	}

	/*如果没设置CLONE_VM标志则需要拷贝内存描述符,线性区，页表*/
	retval = -ENOMEM;
	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

	/* Copy the current MM stuff.. */
	memcpy(mm, oldmm, sizeof(*mm));
	if (!mm_init(mm))
		goto fail_nomem;

	if (init_new_context(tsk,mm))
		goto fail_nocontext;

	/*拷贝线性区和页表*/
	retval = dup_mmap(mm, oldmm);
	if (retval)
		goto free_pt;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;

free_pt:
	mmput(mm);
fail_nomem:
	return retval;

fail_nocontext:
	/*
	 * If init_new_context() failed, we cannot use mmput() to free the mm
	 * because it calls destroy_context()
	 */
	mm_free_pgd(mm);
	free_mm(mm);
	return retval;
}

static inline struct fs_struct *__copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		atomic_set(&fs->count, 1);
		rwlock_init(&fs->lock);
		fs->umask = old->umask;
		read_lock(&old->lock);
		fs->rootmnt = mntget(old->rootmnt);
		fs->root = dget(old->root);
		fs->pwdmnt = mntget(old->pwdmnt);
		fs->pwd = dget(old->pwd);
		if (old->altroot) {
			fs->altrootmnt = mntget(old->altrootmnt);
			fs->altroot = dget(old->altroot);
		} else {
			fs->altrootmnt = NULL;
			fs->altroot = NULL;
		}
		read_unlock(&old->lock);
	}
	return fs;
}

struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	return __copy_fs_struct(old);
}

EXPORT_SYMBOL_GPL(copy_fs_struct);

static inline int copy_fs(unsigned long clone_flags, struct task_struct * tsk)
{
	if (clone_flags & CLONE_FS) {
		atomic_inc(&current->fs->count);
		return 0;
	}
	tsk->fs = __copy_fs_struct(current->fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}

static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fdset;
	int i;

	/* Find the last open fd */
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (fdt->open_fds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}

static struct files_struct *alloc_files(void)
{
	struct files_struct *newf;
	struct fdtable *fdt;

	newf = kmem_cache_alloc(files_cachep, SLAB_KERNEL);
	if (!newf)
		goto out;

	atomic_set(&newf->count, 1);

	spin_lock_init(&newf->file_lock);
	fdt = &newf->fdtab;
	fdt->next_fd = 0;
	fdt->max_fds = NR_OPEN_DEFAULT;
	fdt->max_fdset = __FD_SETSIZE;
	fdt->close_on_exec = &newf->close_on_exec_init;
	fdt->open_fds = &newf->open_fds_init;
	fdt->fd = &newf->fd_array[0];
	INIT_RCU_HEAD(&fdt->rcu);
	fdt->free_files = NULL;
	fdt->next = NULL;
	rcu_assign_pointer(newf->fdt, fdt);
out:
	return newf;
}

static int copy_files(unsigned long clone_flags, struct task_struct * tsk)
{
	struct files_struct *oldf, *newf;
	struct file **old_fds, **new_fds;
	int open_files, size, i, error = 0, expand;
	struct fdtable *old_fdt, *new_fdt;

	/*
	 * A background process may not have any files ...
	 */
	oldf = current->files;
	if (!oldf)
		goto out;
	/*
	 * 如果使用了CLONE_FILES标志，共享files_struct(打开文件表)
	 * 如果没使用CLONE_FILES标志，还要拷贝一份打开文件表
	 * 但是两种情况都共享file对象
	 * 如果拷贝了打开文件表，以后这个进程就可以open并有专属自己的file，
	 * 否则以后open将一直与父进程共享file
	 */
	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}

	/*
	 * Note: we may be using current for both targets (See exec.c)
	 * This works because we cache current->files (old) as oldf. Don't
	 * break this.
	 */
	tsk->files = NULL;
	error = -ENOMEM;
	newf = alloc_files();
	if (!newf)
		goto out;

	spin_lock(&oldf->file_lock);
	old_fdt = files_fdtable(oldf);
	new_fdt = files_fdtable(newf);
	size = old_fdt->max_fdset;
	open_files = count_open_files(old_fdt);
	expand = 0;

	/*
	 * Check whether we need to allocate a larger fd array or fd set.
	 * Note: we're not a clone task, so the open count won't  change.
	 */
	if (open_files > new_fdt->max_fdset) {
		new_fdt->max_fdset = 0;
		expand = 1;
	}
	if (open_files > new_fdt->max_fds) {
		new_fdt->max_fds = 0;
		expand = 1;
	}

	/* if the old fdset gets grown now, we'll only copy up to "size" fds */
	if (expand) {
		spin_unlock(&oldf->file_lock);
		spin_lock(&newf->file_lock);
		error = expand_files(newf, open_files-1);
		spin_unlock(&newf->file_lock);
		if (error < 0)
			goto out_release;
		new_fdt = files_fdtable(newf);
		/*
		 * Reacquire the oldf lock and a pointer to its fd table
		 * who knows it may have a new bigger fd table. We need
		 * the latest pointer.
		 */
		spin_lock(&oldf->file_lock);
		old_fdt = files_fdtable(oldf);
	}

	old_fds = old_fdt->fd;
	new_fds = new_fdt->fd;

	memcpy(new_fdt->open_fds->fds_bits, old_fdt->open_fds->fds_bits, open_files/8);
	memcpy(new_fdt->close_on_exec->fds_bits, old_fdt->close_on_exec->fds_bits, open_files/8);

	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;
		if (f) {
			/*不会拷贝file，只是将file的计数加1*/
			get_file(f);
		} else {
			/*
			 * The fd may be claimed in the fd bitmap but not yet
			 * instantiated in the files array if a sibling thread
			 * is partway through open().  So make sure that this
			 * fd is available to the new process.
			 */
			FD_CLR(open_files - i, new_fdt->open_fds);
		}
		/*只是将父进程的file *拷贝给子进程，不会拷贝file*/
		rcu_assign_pointer(*new_fds++, f);
	}
	spin_unlock(&oldf->file_lock);

	/* compute the remainder to be cleared */
	size = (new_fdt->max_fds - open_files) * sizeof(struct file *);

	/* This is long word aligned thus could use a optimized version */ 
	memset(new_fds, 0, size); 

	if (new_fdt->max_fdset > open_files) {
		int left = (new_fdt->max_fdset-open_files)/8;
		int start = open_files / (8 * sizeof(unsigned long));

		memset(&new_fdt->open_fds->fds_bits[start], 0, left);
		memset(&new_fdt->close_on_exec->fds_bits[start], 0, left);
	}

	tsk->files = newf;
	error = 0;
out:
	return error;

out_release:
	free_fdset (new_fdt->close_on_exec, new_fdt->max_fdset);
	free_fdset (new_fdt->open_fds, new_fdt->max_fdset);
	free_fd_array(new_fdt->fd, new_fdt->max_fds);
	kmem_cache_free(files_cachep, newf);
	goto out;
}

/*
 *	Helper to unshare the files of the current task.
 *	We don't want to expose copy_files internals to
 *	the exec layer of the kernel.
 */

int unshare_files(void)
{
	struct files_struct *files  = current->files;
	int rc;

	if(!files)
		BUG();

	/* This can race but the race causes us to copy when we don't
	   need to and drop the copy */
	if(atomic_read(&files->count) == 1)
	{
		atomic_inc(&files->count);
		return 0;
	}
	rc = copy_files(0, current);
	if(rc)
		current->files = files;
	return rc;
}

EXPORT_SYMBOL(unshare_files);

static inline int copy_sighand(unsigned long clone_flags, struct task_struct * tsk)
{
	struct sighand_struct *sig;

	if (clone_flags & (CLONE_SIGHAND | CLONE_THREAD)) {
		atomic_inc(&current->sighand->count);
		return 0;
	}
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	tsk->sighand = sig;
	if (!sig)
		return -ENOMEM;
	spin_lock_init(&sig->siglock);
	atomic_set(&sig->count, 1);
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));
	return 0;
}

static inline int copy_signal(unsigned long clone_flags, struct task_struct * tsk)
{
	struct signal_struct *sig;
	int ret;

	if (clone_flags & CLONE_THREAD) {
		atomic_inc(&current->signal->count);
		atomic_inc(&current->signal->live);
		return 0;
	}
	sig = kmem_cache_alloc(signal_cachep, GFP_KERNEL);
	tsk->signal = sig;
	if (!sig)
		return -ENOMEM;

	ret = copy_thread_group_keys(tsk);
	if (ret < 0) {
		kmem_cache_free(signal_cachep, sig);
		return ret;
	}

	atomic_set(&sig->count, 1);
	atomic_set(&sig->live, 1);
	init_waitqueue_head(&sig->wait_chldexit);
	sig->flags = 0;
	sig->group_exit_code = 0;
	sig->group_exit_task = NULL;
	sig->group_stop_count = 0;
	sig->curr_target = NULL;
	init_sigpending(&sig->shared_pending);
	INIT_LIST_HEAD(&sig->posix_timers);

	sig->it_real_value = sig->it_real_incr = 0;
	sig->real_timer.function = it_real_fn;
	sig->real_timer.data = (unsigned long) tsk;
	init_timer(&sig->real_timer);

	sig->it_virt_expires = cputime_zero;
	sig->it_virt_incr = cputime_zero;
	sig->it_prof_expires = cputime_zero;
	sig->it_prof_incr = cputime_zero;

	sig->tty = current->signal->tty;
	sig->pgrp = process_group(current);
	sig->session = current->signal->session;
	sig->leader = 0;	/* session leadership doesn't inherit */
	sig->tty_old_pgrp = 0;

	sig->utime = sig->stime = sig->cutime = sig->cstime = cputime_zero;
	sig->nvcsw = sig->nivcsw = sig->cnvcsw = sig->cnivcsw = 0;
	sig->min_flt = sig->maj_flt = sig->cmin_flt = sig->cmaj_flt = 0;
	sig->sched_time = 0;
	INIT_LIST_HEAD(&sig->cpu_timers[0]);
	INIT_LIST_HEAD(&sig->cpu_timers[1]);
	INIT_LIST_HEAD(&sig->cpu_timers[2]);

	task_lock(current->group_leader);
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);
	task_unlock(current->group_leader);

	if (sig->rlim[RLIMIT_CPU].rlim_cur != RLIM_INFINITY) {
		/*
		 * New sole thread in the process gets an expiry time
		 * of the whole CPU time limit.
		 */
		tsk->it_prof_expires =
			secs_to_cputime(sig->rlim[RLIMIT_CPU].rlim_cur);
	}

	return 0;
}

static inline void copy_flags(unsigned long clone_flags, struct task_struct *p)
{
	unsigned long new_flags = p->flags;

	new_flags &= ~(PF_SUPERPRIV | PF_NOFREEZE);
	/*表示子进程还没有发出execve()系统调用*/
	new_flags |= PF_FORKNOEXEC;
	if (!(clone_flags & CLONE_PTRACE))
		p->ptrace = 0;
	p->flags = new_flags;
}

asmlinkage long sys_set_tid_address(int __user *tidptr)
{
	current->clear_child_tid = tidptr;

	return current->pid;
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
/*
 * @clone_flags: CLONE_XXX标志,低字节指定子进程结束时发送到父进程的信号代码，通常选择SIGCHLD
 *               剩余3字节给clone标志组用于编码
 * @stack_start: 表示把用户态堆栈指针赋给子进程的esp寄存器。调用进程应该总是为子进程分配新的堆栈???
 * @regs: 指向通用寄存器值的指针，通用寄存器的值是在从用户态切换到内核态时被保存到内核态堆栈中的
 * @stack_size:未使用（总是被设置为0）
 * @parent_tidptr：表示父进程的用户态变量地址，该父进程与新轻量级进程有相同的PID。
 *                 只有在CLONE_PARENT_SETTID被设置时才有意义
 * @child_tidptr：表示新轻量级进程的用户态变量地址，该进程具有这一类进程的PID
 *                只有在CLONE_CHILD_SETTID被设置时才有意义
 * @pid: 子进程的pid号
 */
static task_t *copy_process(unsigned long clone_flags,
				 unsigned long stack_start,
				 struct pt_regs *regs,
				 unsigned long stack_size,
				 int __user *parent_tidptr,
				 int __user *child_tidptr,
				 int pid)
{
	int retval;
	struct task_struct *p = NULL;

	/*子进程需要独立命名空间 和 与父进程共享根目录和当前目录有冲突*/
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	/*同一线程组的轻量级进程必须共享信号*/
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	/*共享信号处理程序的轻量级进程也必须共享内存描述符*/
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	/*安全性检查*/
	retval = security_task_create(clone_flags);
	if (retval)
		goto fork_out;

	retval = -ENOMEM;
	/*将父进程的进程描述符拷贝给子进程*/
	p = dup_task_struct(current);
	if (!p)
		goto fork_out;

	retval = -EAGAIN;
	/*用户所拥有的进程数超过了进程的最大资源???*/
	if (atomic_read(&p->user->processes) >=
			p->signal->rlim[RLIMIT_NPROC].rlim_cur) {
		if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RESOURCE) &&
				p->user != &root_user)
			goto bad_fork_free;
	}

	/*递增使用计数值*/
	atomic_inc(&p->user->__count);
	/*递增用户进程数*/
	atomic_inc(&p->user->processes);
	get_group_info(p->group_info);

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
	/*
	 * 检查系统中进程数量是否超过最大进程数
	 * 总的原则是thread_info描述符和内核栈所占空间不超过物理内存的1/8
	 */
	if (nr_threads >= max_threads)
		goto bad_fork_cleanup_count;

	/*如果实现新进程的执行域和可执行格式的内核函数都包含在内核模块中，则递增它们的使用计数器*/
	if (!try_module_get(p->thread_info->exec_domain->module))
		goto bad_fork_cleanup_count;

	if (p->binfmt && !try_module_get(p->binfmt->module))
		goto bad_fork_cleanup_put_domain;

	/*初始化进程调用execve系统调用的次数*/
	p->did_exec = 0;
	/*拷贝clone_floags*/
	copy_flags(clone_flags, p);
	/*初始化新进程的pid*/
	p->pid = pid;
	retval = -EFAULT;
	/*如果设置了CLONE_PARENT_SETTID标志,把子进程pid复制到parent_tidptr指向的用户态变量中*/
	if (clone_flags & CLONE_PARENT_SETTID)
		if (put_user(p->pid, parent_tidptr))
			goto bad_fork_cleanup;

	p->proc_dentry = NULL;

	/*初始化孩子进程和兄弟进程链表*/
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	p->vfork_done = NULL;
	/*初始化子进程的锁*/
	spin_lock_init(&p->alloc_lock);
	spin_lock_init(&p->proc_lock);

	/*清除子进程signal pending*/
	clear_tsk_thread_flag(p, TIF_SIGPENDING);
	init_sigpending(&p->pending);

	/*初始化定时器及时间统计相关*/
	p->utime = cputime_zero;
	p->stime = cputime_zero;
 	p->sched_time = 0;
	p->rchar = 0;		/* I/O counter: bytes read */
	p->wchar = 0;		/* I/O counter: bytes written */
	p->syscr = 0;		/* I/O counter: read syscalls */
	p->syscw = 0;		/* I/O counter: write syscalls */
	acct_clear_integrals(p);

 	p->it_virt_expires = cputime_zero;
	p->it_prof_expires = cputime_zero;
 	p->it_sched_expires = 0;
 	INIT_LIST_HEAD(&p->cpu_timers[0]);
 	INIT_LIST_HEAD(&p->cpu_timers[1]);
 	INIT_LIST_HEAD(&p->cpu_timers[2]);

	/*初始化大内核锁计数器为-1*/
	p->lock_depth = -1;		/* -1 = no lock */
	do_posix_clock_monotonic_gettime(&p->start_time);
	p->security = NULL;
	p->io_context = NULL;
	p->io_wait = NULL;
	p->audit_context = NULL;
#ifdef CONFIG_NUMA
 	p->mempolicy = mpol_copy(p->mempolicy);
 	if (IS_ERR(p->mempolicy)) {
 		retval = PTR_ERR(p->mempolicy);
 		p->mempolicy = NULL;
 		goto bad_fork_cleanup;
 	}
#endif

	p->tgid = p->pid;
	if (clone_flags & CLONE_THREAD)
		p->tgid = current->tgid;

	if ((retval = security_task_alloc(p)))
		goto bad_fork_cleanup_policy;
	if ((retval = audit_alloc(p)))
		goto bad_fork_cleanup_security;
	
	/* copy all the process information */
	if ((retval = copy_semundo(clone_flags, p)))
		goto bad_fork_cleanup_audit;
	if ((retval = copy_files(clone_flags, p)))
		goto bad_fork_cleanup_semundo;
	if ((retval = copy_fs(clone_flags, p)))
		goto bad_fork_cleanup_files;
	if ((retval = copy_sighand(clone_flags, p)))
		goto bad_fork_cleanup_fs;
	if ((retval = copy_signal(clone_flags, p)))
		goto bad_fork_cleanup_sighand;
	if ((retval = copy_mm(clone_flags, p)))
		goto bad_fork_cleanup_signal;
	if ((retval = copy_keys(clone_flags, p)))
		goto bad_fork_cleanup_mm;
	if ((retval = copy_namespace(clone_flags, p)))
		goto bad_fork_cleanup_keys;
	
	/*用发出clone系统调用时CPU寄存器的值（保存在父进程内核栈中）来初始化子进程的内核栈*/
	retval = copy_thread(0, clone_flags, stack_start, stack_size, p, regs);
	if (retval)
		goto bad_fork_cleanup_namespace;

	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr: NULL;

	/*
	 * Syscall tracing should be turned off in the child regardless
	 * of CLONE_PTRACE.
	 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);
#ifdef TIF_SYSCALL_EMU
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif

	/* Our parent execution domain becomes current domain
	   These must match for thread signalling to apply */
	   
	p->parent_exec_id = p->self_exec_id;

	/* ok, now we should be set up.. */
	/*最低字节指定子进程结束时发送到父进程的信号代码???*/
	p->exit_signal = (clone_flags & CLONE_THREAD) ? -1 : (clone_flags & CSIGNAL);
	p->pdeath_signal = 0;
	p->exit_state = 0;

	/*
	 * Ok, make it visible to the rest of the system.
	 * We dont wake it up yet.
	 */
	p->group_leader = p;
	INIT_LIST_HEAD(&p->ptrace_children);
	INIT_LIST_HEAD(&p->ptrace_list);

	/* Perform scheduler related setup. Assign this task to a CPU. */
	/*新进程调度程序数据结构初始化*/
	sched_fork(p, clone_flags);

	/* Need tasklist lock for parent etc handling! */
	write_lock_irq(&tasklist_lock);

	/*
	 * The task hasn't been attached yet, so its cpus_allowed mask will
	 * not be changed, nor will its assigned CPU.
	 *
	 * The cpus_allowed mask of the parent may have changed after it was
	 * copied first time - so re-copy it here, then check the child's CPU
	 * to ensure it is on a valid CPU (and if not, just force it back to
	 * parent's CPU). This avoids alot of nasty races.
	 */
	p->cpus_allowed = current->cpus_allowed;
	if (unlikely(!cpu_isset(task_cpu(p), p->cpus_allowed) ||
			!cpu_online(task_cpu(p))))
		/*设置进程的cpu为本地cpu*/
		set_task_cpu(p, smp_processor_id());

	/*
	 * Check for pending SIGKILL! The new thread should not be allowed
	 * to slip out of an OOM kill. (or normal SIGKILL.)
	 */
	if (sigismember(&current->pending.signal, SIGKILL)) {
		write_unlock_irq(&tasklist_lock);
		retval = -EINTR;
		goto bad_fork_cleanup_namespace;
	}

	/* CLONE_PARENT re-uses the old parent */
	/*初始化表示父子关系*/
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
		p->real_parent = current->real_parent;
	else
		p->real_parent = current;
	p->parent = p->real_parent;

	if (clone_flags & CLONE_THREAD) {
		spin_lock(&current->sighand->siglock);
		/*
		 * Important: if an exit-all has been started then
		 * do not create this new thread - the whole thread
		 * group is supposed to exit anyway.
		 */
		if (current->signal->flags & SIGNAL_GROUP_EXIT) {
			spin_unlock(&current->sighand->siglock);
			write_unlock_irq(&tasklist_lock);
			retval = -EAGAIN;
			goto bad_fork_cleanup_namespace;
		}
		p->group_leader = current->group_leader;

		if (current->signal->group_stop_count > 0) {
			/*
			 * There is an all-stop in progress for the group.
			 * We ourselves will stop as soon as we check signals.
			 * Make the new thread part of that group stop too.
			 */
			current->signal->group_stop_count++;
			set_tsk_thread_flag(p, TIF_SIGPENDING);
		}

		if (!cputime_eq(current->signal->it_virt_expires,
				cputime_zero) ||
		    !cputime_eq(current->signal->it_prof_expires,
				cputime_zero) ||
		    current->signal->rlim[RLIMIT_CPU].rlim_cur != RLIM_INFINITY ||
		    !list_empty(&current->signal->cpu_timers[0]) ||
		    !list_empty(&current->signal->cpu_timers[1]) ||
		    !list_empty(&current->signal->cpu_timers[2])) {
			/*
			 * Have child wake up on its first tick to check
			 * for process CPU timers.
			 */
			p->it_prof_expires = jiffies_to_cputime(1);
		}

		spin_unlock(&current->sighand->siglock);
	}

	/*
	 * inherit ioprio
	 */
	p->ioprio = current->ioprio;

	/*将进程链入进程描述符表*/
	SET_LINKS(p);
	/*如果子进程必须被跟踪*/
	if (unlikely(p->ptrace & PT_PTRACED))
		/*将current->parent赋值给p->parent,并将子进程p插入调试程序跟踪链表*/
		__ptrace_link(p, current->parent);

	cpuset_fork(p);

	/*把子进程p的描述符插入pidhash[PIDTYPE_PID]散列表*/
	attach_pid(p, PIDTYPE_PID, p->pid);
	/*把子进程p的描述符插入pidhash[PIDTYPE_TGID]散列表*/
	attach_pid(p, PIDTYPE_TGID, p->tgid);
	/*如果p是所在线程的领头进程*/
	if (thread_group_leader(p)) {
		/*把子进程p的描述符插入pidhash[PIDTYPE_PGID]散列表*/
		attach_pid(p, PIDTYPE_PGID, process_group(p));
		/*把子进程p的描述符插入pidhash[PIDTYPE_SID]散列表*/
		attach_pid(p, PIDTYPE_SID, p->signal->session);
		if (p->pid)
			__get_cpu_var(process_counts)++;
	}

	if (!current->signal->tty && p->signal->tty)
		p->signal->tty = NULL;

	/*递增idle进程数*/
	nr_threads++;
	/*增加被创建进程的数量*/
	total_forks++;
	write_unlock_irq(&tasklist_lock);
	retval = 0;

fork_out:
	if (retval)
		return ERR_PTR(retval);
	/*返回子进程描述符*/
	return p;

bad_fork_cleanup_namespace:
	exit_namespace(p);
bad_fork_cleanup_keys:
	exit_keys(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	exit_signal(p);
bad_fork_cleanup_sighand:
	exit_sighand(p);
bad_fork_cleanup_fs:
	exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_security:
	security_task_free(p);
bad_fork_cleanup_policy:
#ifdef CONFIG_NUMA
	mpol_free(p->mempolicy);
#endif
bad_fork_cleanup:
	if (p->binfmt)
		module_put(p->binfmt->module);
bad_fork_cleanup_put_domain:
	module_put(p->thread_info->exec_domain->module);
bad_fork_cleanup_count:
	put_group_info(p->group_info);
	atomic_dec(&p->user->processes);
	free_uid(p->user);
bad_fork_free:
	free_task(p);
	goto fork_out;
}

struct pt_regs * __devinit __attribute__((weak)) idle_regs(struct pt_regs *regs)
{
	memset(regs, 0, sizeof(struct pt_regs));
	return regs;
}

task_t * __devinit fork_idle(int cpu)
{
	task_t *task;
	struct pt_regs regs;

	task = copy_process(CLONE_VM, 0, idle_regs(&regs), 0, NULL, NULL, 0);
	if (!task)
		return ERR_PTR(-ENOMEM);
	init_idle(task, cpu);
	unhash_process(task);
	return task;
}

static inline int fork_traceflag (unsigned clone_flags)
{
	if (clone_flags & CLONE_UNTRACED)
		return 0;
	else if (clone_flags & CLONE_VFORK) {
		if (current->ptrace & PT_TRACE_VFORK)
			return PTRACE_EVENT_VFORK;
	} else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		if (current->ptrace & PT_TRACE_CLONE)
			return PTRACE_EVENT_CLONE;
	} else if (current->ptrace & PT_TRACE_FORK)
		return PTRACE_EVENT_FORK;

	return 0;
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 */
/*
 * fork()/vfork()/clone()系统调用/kernel_thread()都将调用do_fork()
 * fork()是将父进程的全部资源拷贝给子进程
 * vfork()是将父进程除mm_struct的所有资源拷贝给子进程
 * clone()是通过CLONE_XXX指定将哪些资源从父进程拷贝到子进程
 * 
 * @clone_flags: CLONE_XXX标志,低字节指定子进程结束时发送到父进程的信号代码，通常选择SIGCHLD
 *               剩余3字节给clone标志组用于编码
 * @stack_start: 表示把用户态堆栈指针赋给子进程的esp寄存器。调用进程应该总是为子进程分配新的堆栈???
 * @regs: 指向通用寄存器值的指针，通用寄存器的值是在从用户态切换到内核态时被保存到内核态堆栈中的
 * @stack_size:未使用（总是被设置为0）
 * @parent_tidptr：表示父进程的用户态变量地址，该父进程与新轻量级进程有相同的PID。
 *                 只有在CLONE_PARENT_SETTID被设置时才有意义
 * @child_tidptr：表示新轻量级进程的用户态变量地址，该进程具有这一类进程的PID
 *                只有在CLONE_CHILD_SETTID被设置时才有意义
 */
long do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      struct pt_regs *regs,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr)
{
	struct task_struct *p;
	int trace = 0;
	/*查找pidmap_array位图，分配一个pid*/
	long pid = alloc_pidmap();

	if (pid < 0)
		return -EAGAIN;
	if (unlikely(current->ptrace)) {
		trace = fork_traceflag (clone_flags);
		if (trace)
			clone_flags |= CLONE_PTRACE;
	}

	/*复制进程描述符，返回刚创建的task_struct描述符的地址*/
	p = copy_process(clone_flags, stack_start, regs, stack_size, parent_tidptr, child_tidptr, pid);
	/*
	 * Do this prior waking up the new thread - the thread pointer
	 * might get invalid after that point, if the thread exits quickly.
	 */
	if (!IS_ERR(p)) {
		struct completion vfork;

		if (clone_flags & CLONE_VFORK) {
			p->vfork_done = &vfork;
			init_completion(&vfork);
		}
		/*
		 * 如果设置了CLONE_STOPPED标志或必须跟踪子进程
		 */
		if ((p->ptrace & PT_PTRACED) || (clone_flags & CLONE_STOPPED)) {
			/*
			 * We'll start up with an immediate SIGSTOP.
			 */
			/*
			 * 为子进程增加挂起的SIGSTOP信号
			 * 在另一个进程（假设跟踪进程或父进程）把子进程的状态恢复为TASK_RUNNING之前（通常是发SIGCONT信号）
			 * 子进程将一直保持TASK_STOPPED状态
			 */
			sigaddset(&p->pending.signal, SIGSTOP);
			set_tsk_thread_flag(p, TIF_SIGPENDING);
		}

		if (!(clone_flags & CLONE_STOPPED))
			/* 将新创建的进程加入就绪队列，等待调度器调度*/
			wake_up_new_task(p, clone_flags);
		else
			p->state = TASK_STOPPED;

		/*如果父进程被跟踪*/
		if (unlikely (trace)) {
			current->ptrace_message = pid;
			/*
			 * 使当前进程停止运行，并向当前进程的父进程发送SIGCHLD信号
			 * 子进程的祖父进程是跟踪父进程的debugger进程
			 * SIGCHLD信号通知debugger进程：current进程已经创建了一个子进程，
			 *                              可以通过查找current->ptrace_message字段获得子进程的PID
			 */
			ptrace_notify ((trace << 8) | SIGTRAP);
		}

		if (clone_flags & CLONE_VFORK) {
			/*将current(父进程)插入等待队列，并挂起父进程直到子进程释放自己的内存地址空间（子进程结束或执行新的程序）*/
			wait_for_completion(&vfork);
			if (unlikely (current->ptrace & PT_TRACE_VFORK_DONE))
				ptrace_notify ((PTRACE_EVENT_VFORK_DONE << 8) | SIGTRAP);
		}
	} else {
		free_pidmap(pid);
		pid = PTR_ERR(p);
	}
	/*返回子进程的PID*/
	return pid;
}

void __init proc_caches_init(void)
{
	sighand_cachep = kmem_cache_create("sighand_cache",
			sizeof(struct sighand_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	signal_cachep = kmem_cache_create("signal_cache",
			sizeof(struct signal_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	files_cachep = kmem_cache_create("files_cache", 
			sizeof(struct files_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	fs_cachep = kmem_cache_create("fs_cache", 
			sizeof(struct fs_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	vm_area_cachep = kmem_cache_create("vm_area_struct",
			sizeof(struct vm_area_struct), 0,
			SLAB_PANIC, NULL, NULL);
	mm_cachep = kmem_cache_create("mm_struct",
			sizeof(struct mm_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

