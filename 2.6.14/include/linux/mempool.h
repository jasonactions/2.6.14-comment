/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

/*
 * 内存池描述符,内存池通常叠加在slab分配器之上，
 * 内存池可用来存放从整个页框到kmalloc分配的小内存区
 */
typedef struct mempool_s {
	spinlock_t lock;
	/*内存池中元素的最大个数*/
	int min_nr;		/* nr of elements at *elements */
	/*当前内存池中元素的个数,如果大于0表示可以分配*/
	int curr_nr;		/* Current nr of elements at *elements */
	/*指向一个指针数组，该指针数组由指向保留元素的指针组成*/
	void **elements;

	/*
	 * 池的拥有者可获得的私有数据
	 * 当内存池元素是slab对象时，此字段存放了slab高速缓存描述符的地址
	 */
	void *pool_data;
	/*分配一个元素的方法*/
	mempool_alloc_t *alloc;
	/*释放一个元素的方法*/
	mempool_free_t *free;
	/*当内存池为空时使用等待队列*/
	wait_queue_head_t wait;
} mempool_t;

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data, int nid);

extern int mempool_resize(mempool_t *pool, int new_min_nr, gfp_t gfp_mask);
extern void mempool_destroy(mempool_t *pool);
extern void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab that is passed in through pool_data.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);

#endif /* _LINUX_MEMPOOL_H */
