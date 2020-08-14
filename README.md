主要对Linux 2.6.14的IO, 内存管理和进程管理部分进行注释，通过阅读代码并添加注释，来深入理解内核的实现机制和原理。主要参考书籍为《深入理解Linux内核》第三版

下面列出了各个场景的主要函数：

# generic block
## include/linux/fs.h
struct block_device_operations
## include/linux/genhd.h
struct gendisk
struct hd_struct
## include/linux/blkdev.h
struct request_queue 
struct request
struct block_device
## include/linux/elevator.h
struct elevator_queue  

## fs/block_dev.c
struct block_device *bdget(dev_t dev) 

## block/genhd.c
struct gendisk *alloc_disk_node(int minors, int node_id) 
int register_blkdev(unsigned int major, const char *name)

void blk_queue_make_request(request_queue_t * q, make_request_fn * mfn)
void add_disk(struct gendisk *disk) 

## fs/bio.c
struct bio *bio_alloc(gfp_t gfp_mask, int nr_iovecs) 

## block/ll_rw_blk.c   
void generic_make_request(struct bio *bio)
void submit_bio(int rw, struct bio *bio) 

struct request *blk_get_request(request_queue_t *q, int rw, gfp_t gfp_mask) 
void blk_put_request(struct request *req) 

long blk_congestion_wait(int rw, long timeout) 

void blk_plug_device(request_queue_t *q) 
int blk_remove_plug(request_queue_t *q)
void generic_unplug_device(request_queue_t *q) 

request_queue_t *blk_alloc_queue(gfp_t gfp_mask)
request_queue_t *blk_init_queue(request_fn_proc *rfn, spinlock_t *lock) 
void blk_queue_hardsect_size(request_queue_t *q, unsigned short size)

# page/buffer cache
## include/linux/bio.h
struct bio;
struct bio_vec;
## include/linux/buufer_head.h
struct buffer_head;
## fs/buffer.c
static inline int grow_buffers(struct block_device *bdev, sector_t block, int size) 
int try_to_release_page(struct page *page, gfp_t gfp_mask)

struct buffer_head *__find_get_block(struct block_device *bdev, sector_t block, int size)
struct buffer_head *__getblk(struct block_device *bdev, sector_t block, int size) 
struct buffer_head *__bread(struct block_device *bdev, sector_t block, int size)

static void init_page_buffers(struct page *page, struct block_device *bdev,
		sector_t block, int size)

int submit_bh(int rw, struct buffer_head * bh)
void ll_rw_block(int rw, int nr, struct buffer_head *bhs[])

## mm/pdflush.c
static int pdflush(void *dummy)
static int __init pdflush_init(void)	
int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0) 

## mm/page-writeback.c
static void get_dirty_limits(struct writeback_state *wbs, long *pbackground, long *pdirty,
		struct address_space *mapping)
static void background_writeout(unsigned long _min_pages)
int wakeup_pdflush(long nr_pages) 

void __init page_writeback_init(void) 
static void wb_kupdate(unsigned long arg) 
static void wb_timer_fn(unsigned long unused) 

# vfs
## include/linux/fs.h
struct super_block;
struct inode;
struct file;
## include/linux/dcache.h
struct dentry;
struct dentry_operations;
## include/linux/fs_struct.h
struct fs_struct
## include/linux/namespace.h
struct namespace;
## include/linux/namei.h
struct nameidata;

## fs/file_table.c
void __init files_init(unsigned long mempages) 
struct file fastcall *fget(unsigned int fd)
void fastcall fput(struct file *file) 
struct file fastcall *fget_light(unsigned int fd, int *fput_needed)
static inline void fput_light(struct file *file, int fput_needed) 

## fs/filesystems.c
int register_filesystem(struct file_system_type * fs) 
struct file_system_type *get_fs_type(const char *name)

## fs/namespace.c
struct vfsmount *alloc_vfsmnt(const char *name)
void free_vfsmnt(struct vfsmount *mnt)
struct vfsmount *lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)

asmlinkage long sys_mount(char __user * dev_name, char __user * dir_name,
                          char __user * type, unsigned long flags,
                          void __user * data)
asmlinkage long sys_umount(char __user * name, int flags) 

## fs/open.c
asmlinkage long sys_open(const char __user *filename, int flags, int mode)
asmlinkage long sys_close(unsigned int fd) 

## fs/read_write.c
asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
asmlinkage ssize_t sys_write(unsigned int fd, const char __user * buf, size_t count)

# READ FILE
## include/linux/fs.h
read_descriptor_t
## include/linux/uio.h
struct iovec
## linux/aio.h
struct kiocb kiocb

## mm/filemap.c
ssize_t generic_file_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)

## fs/mpage.c
static struct bio *   do_mpage_readpage(struct bio *bio, struct page *page, unsigned nr_pages,
                      sector_t *last_block_in_bio, get_block_t get_block)
int mpage_readpage(struct page *page, get_block_t get_block)

## fs/block_dev.c
int block_read_full_page(struct page *page, get_block_t *get_block) 
static int blkdev_readpage(struct file * file, struct page * page)

# READ AHEAD
## include/linux/fs.h
struct file_ra_state

## mm/madvise.c
asmlinkage long sys_madvise(unsigned long start, size_t len_in, int behavior) 

## mm/readahead.c
static int 
blockable_page_cache_readahead(struct address_space *mapping, struct file *filp,
                        unsigned long offset, unsigned long nr_to_read,
                        struct file_ra_state *ra, int block)
unsigned long page_cache_readahead(struct address_space *mapping, struct file_ra_state *ra,
                        struct file *filp, unsigned long offset, unsigned long req_size) 

# WRITE FILE
## include/linux/uio.h
struct iovec
## include/linux/pagevec.h 
struct pagevec
## include/linux/fs.h

## fs/buffer.c
static int __block_prepare_write(struct inode *inode, struct page *page,
                	     unsigned from, unsigned to, get_block_t *get_block)
int block_prepare_write(struct page *page, unsigned from, unsigned to,                                                                                                           
                        get_block_t *get_block) 

static int __block_commit_write(struct inode *inode, struct page *page,  
                	     unsigned from, unsigned to)
int block_commit_write(struct page *page, unsigned from, unsigned to) 

## mm/filemap.c
ssize_t generic_file_write(struct file *file, const char __user *buf,                                                                                                             
                        size_t count, loff_t *ppos) 

# 脏页写入磁盘
## fs/mpage.c
static struct bio *__mpage_writepage(struct bio *bio, struct page *page, get_block_t get_block,                                                                                 
        		         sector_t *last_block_in_bio, int *ret, struct writeback_control *wbc,                                                                                         
        		         writepage_t writepage_fn)                                                                                                                                                

int mpage_writepages(struct address_space *mapping,
                	struct writeback_control *wbc, get_block_t get_block)

# 创建内存映射
## mm/filemap.c
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)

## mm/mmap.c
unsigned long do_mmap_pgoff(struct file * file, unsigned long addr,
              unsigned long len, unsigned long prot,
			           unsigned long flags, unsigned long pgoff) 

## arch/arm/kernel/sys_arm.c
inline long do_mmap2(
        		   unsigned long addr, unsigned long len,
        		   unsigned long prot, unsigned long flags,
        		   unsigned long fd, unsigned long pgoff)

# 撤销内存映射
int do_munmap(struct mm_struct *mm, unsigned long start, size_t len)

# 内存映射请求调页
## mm/filemap.c
struct page *filemap_nopage(struct vm_area_struct *area,  
			            unsigned long address, int *type)
## mm/memory.c 
static int do_no_page(struct mm_struct *mm, struct vm_area_struct *vma,
			           unsigned long address, pte_t *page_table, pmd_t *pmd,
			           int write_access)

# 内存映射脏页刷新到磁盘
## mm/msync.c
static int msync_interval(struct vm_area_struct *vma, 
			          unsigned long addr, unsigned long end, int flags)
             asmlinkage long sys_msync(unsigned long start, size_t len, int flags) 

# 非线性内存映射
## mm/fremap.c 
int filemap_populate(struct vm_area_struct *vma, unsigned long addr,
			          unsigned long len, pgprot_t prot, unsigned long pgoff, int nonblock) 

asmlinkage long sys_remap_file_pages(unsigned long start, unsigned long size,
			         unsigned long __prot, unsigned long pgoff, unsigned long flags)

# 直接I/O传送
## fs/direct-io.c 
ssize_t
__blockdev_direct_IO(int rw, struct kiocb *iocb, struct inode *inode,
			         struct block_device *bdev, const struct iovec *iov, loff_t offset, 
unsigned long nr_segs, get_blocks_t get_blocks, dio_iodone_t end_io,
			         int dio_lock_type)

# 异步IO
## include/linux/aio.h
struct kioctx

## mm/filemap.c 
static ssize_t generic_file_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
			        loff_t offset, unsigned long nr_segs)
ssize_t generic_file_aio_write_nolock(struct kiocb *iocb, const struct iovec *iov, 
			        unsigned long nr_segs, loff_t *ppos)
ssize_t __generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
			        unsigned long nr_segs, loff_t *ppos) 

## fs/aio.c  
static ssize_t aio_pread(struct kiocb *iocb)

static ssize_t aio_run_iocb(struct kiocb *iocb

asmlinkage long sys_io_submit(aio_context_t ctx_id, long nr,
			struct iocb __user * __user *iocbpp) 
