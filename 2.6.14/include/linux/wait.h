#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */

#define __WNOTHREAD	0x20000000	/* Don't wait on children of other threads in this group */
#define __WALL		0x40000000	/* Wait on all children, regardless of type */
#define __WCLONE	0x80000000	/* Wait only on non-SIGCHLD children */

/* First argument to waitid: */
#define P_ALL		0
#define P_PID		1
#define P_PGID		2

#ifdef __KERNEL__

#include <linux/config.h>
#include <linux/list.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>
#include <asm/system.h>
#include <asm/current.h>

/*
 * 等待队列中的元素
 * 每个元素代表一个睡眠进程，该进程等待某一事件发生
 */
typedef struct __wait_queue wait_queue_t;
/*自定义等待队列唤醒函数*/
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int sync, void *key);
/*默认等待队列唤醒函数*/
int default_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);

/*
 * 等待队列元素
 * 代表一个进程插入到等待队列
 * 实现了在事件上的条件等待，表示一组睡眠的进程，当某一条件为真时，内核唤醒他们
 * 每个等待队列都有一个等待队列头
 */
struct __wait_queue {
	/*
	 * 两种睡眠进程：
	 * 互斥进程（flags:1）:内核有选择的唤醒；
	 * 非互斥进程（flags:0）：内核在事件发生时唤醒
	 */
	unsigned int flags;
#define WQ_FLAG_EXCLUSIVE	0x01
	/*可存放进程描述符地址*/
	void *private;
	/*用于唤醒与本等待队列元素对应的进程或进程组的唤醒函数*/
	wait_queue_func_t func;
	/*用于连接进程组的进程链表连接件*/
	struct list_head task_list;
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
};

struct wait_bit_queue {
	struct wait_bit_key key;
	wait_queue_t wait;
};
/*等待队列(头)*/
struct __wait_queue_head {
	spinlock_t lock;
	/*等待队列链表的头*/
	struct list_head task_list;
};
typedef struct __wait_queue_head wait_queue_head_t;


/*
 * Macros for declaration and initialisaton of the datatypes
 */

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private	= tsk,						\
	.func		= default_wake_function,			\
	.task_list	= { NULL, NULL } }

/*定义并初始化一个等待队列元素*/
#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= SPIN_LOCK_UNLOCKED,				\
	.task_list	= { &(name).task_list, &(name).task_list } }

/*定义并初始化一个等待队列*/
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }

/*初始化等待队列*/
static inline void init_waitqueue_head(wait_queue_head_t *q)
{
	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->task_list);
}

/*初始化动态分配的等待队列元素*/
static inline void init_waitqueue_entry(wait_queue_t *q, struct task_struct *p)
{
	q->flags = 0;
	q->private = p;
	/*用于唤醒非互斥进程*/
	q->func = default_wake_function;
}

/*初始化动态分配的等待队列元素，使用自定义唤醒函数*/
static inline void init_waitqueue_func_entry(wait_queue_t *q,
					wait_queue_func_t func)
{
	q->flags = 0;
	q->private = NULL;
	q->func = func;
}

/*判断等待队列是否被激活*/
static inline int waitqueue_active(wait_queue_head_t *q)
{
	return !list_empty(&q->task_list);
}

/*
 * Used to distinguish between sync and async io wait context:
 * sync i/o typically specifies a NULL wait queue entry or a wait
 * queue entry bound to a task (current task) to wake up.
 * aio specifies a wait queue entry with an async notification
 * callback routine, not associated with any task.
 */
/*判断等待队列元素对应的进程唤醒后是否要与当前运行进程的优先级比较,true则不比较*/
#define is_sync_wait(wait)	(!(wait) || ((wait)->private))

extern void FASTCALL(add_wait_queue(wait_queue_head_t *q, wait_queue_t * wait));
extern void FASTCALL(add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t * wait));
extern void FASTCALL(remove_wait_queue(wait_queue_head_t *q, wait_queue_t * wait));

/*将等待队列元素new加入等待队列head*/
static inline void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

/*
 * Used for wake-one threads:
 */
/*将等待队列元素new加入等待队列head的末尾*/
static inline void __add_wait_queue_tail(wait_queue_head_t *head,
						wait_queue_t *new)
{
	list_add_tail(&new->task_list, &head->task_list);
}

/*将等待队列元素old从等待队列head删除*/
static inline void __remove_wait_queue(wait_queue_head_t *head,
							wait_queue_t *old)
{
	list_del(&old->task_list);
}

void FASTCALL(__wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key));
extern void FASTCALL(__wake_up_locked(wait_queue_head_t *q, unsigned int mode));
extern void FASTCALL(__wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr));
void FASTCALL(__wake_up_bit(wait_queue_head_t *, void *, int));
int FASTCALL(__wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned));
int FASTCALL(__wait_on_bit_lock(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned));
void FASTCALL(wake_up_bit(void *, int));
int FASTCALL(out_of_line_wait_on_bit(void *, int, int (*)(void *), unsigned));
int FASTCALL(out_of_line_wait_on_bit_lock(void *, int, int (*)(void *), unsigned));
wait_queue_head_t *FASTCALL(bit_waitqueue(void *, int));

/*唤醒等待队列x上mode为TASK_UNINTERRUPTIBLE|TASK_INTERRUPTIBLE的所有非互斥进程和1个互斥进程*/
#define wake_up(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 1, NULL)
/*唤醒等待队列x上mode为TASK_UNINTERRUPTIBLE|TASK_INTERRUPTIBLE的所有非互斥进程和nr个互斥进程*/
#define wake_up_nr(x, nr)		__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, nr, NULL)
/*唤醒等待队列x上mode为TASK_UNINTERRUPTIBLE|TASK_INTERRUPTIBLE的所有非互斥进程和所有互斥进程*/
#define wake_up_all(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 0, NULL)
/*唤醒等待队列x上mode为TASK_INTERRUPTIBLE的所有非互斥进程和1个互斥进程*/
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
/*唤醒等待队列x上mode为TASK_UNINTERRUPTIBLE|TASK_INTERRUPTIBLE的所有非互斥进程和nr个互斥进程*/
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
/*唤醒等待队列x上mode为TASK_UNINTERRUPTIBLE|TASK_INTERRUPTIBLE的所有非互斥进程和所有的互斥进程*/
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
/*等待队列已经持有spin_lock时调用*/
#define	wake_up_locked(x)		__wake_up_locked((x), TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE)
/*不会检查被唤醒进程的优先级是否高于系统中正在运行进程的优先级*/
#define wake_up_interruptible_sync(x)   __wake_up_sync((x),TASK_INTERRUPTIBLE, 1)

/*等待条件condition为真，否则一直睡眠且不可被信号打断*/
#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
/*进程在等待队列wq上睡眠，一直到condition为真*/
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)

#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, and the remaining
 * jiffies if the condition evaluated to true before the timeout elapsed.
 */
/*程在等待队列wq上睡眠，一直到condition为真或超时时间到*/
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})

#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_interruptible - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
/*进程在等待队列wq上睡眠，一直到condition为真，或接收到信号*/
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})

#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/**
 * wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, -ERESTARTSYS if it
 * was interrupted by a signal, and the remaining jiffies otherwise
 * if the condition evaluated to true before the timeout elapsed.
 */
/*进程在等待队列wq上睡眠，一直到condition为真，收到信号或超时时间到*/
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

/*互斥进程在等待队列wq上睡眠，一直到condition为真或收到信号*/
#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})

/*
 * Must be called with the spinlock in the wait_queue_head_t held.
 */
/*在等待持锁的情况下，将等待队列元素添加到等待队列q的末尾*/
static inline void add_wait_queue_exclusive_locked(wait_queue_head_t *q,
						   wait_queue_t * wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_tail(q,  wait);
}

/*
 * Must be called with the spinlock in the wait_queue_head_t held.
 */
/*在等待持锁的情况下，将等待队列元素wait从等待队列q中删除*/
static inline void remove_wait_queue_locked(wait_queue_head_t *q,
					    wait_queue_t * wait)
{
	__remove_wait_queue(q,  wait);
}

/*
 * These are the old interfaces to sleep waiting for an event.
 * They are racy.  DO NOT use them, use the wait_event* interfaces above.  
 * We plan to remove these interfaces during 2.7.
 */
extern void FASTCALL(sleep_on(wait_queue_head_t *q));
extern long FASTCALL(sleep_on_timeout(wait_queue_head_t *q,
				      signed long timeout));
extern void FASTCALL(interruptible_sleep_on(wait_queue_head_t *q));
extern long FASTCALL(interruptible_sleep_on_timeout(wait_queue_head_t *q,
						    signed long timeout));

/*
 * Waitqueues which are removed from the waitqueue_head at wakeup time
 */
void FASTCALL(prepare_to_wait(wait_queue_head_t *q,
				wait_queue_t *wait, int state));
void FASTCALL(prepare_to_wait_exclusive(wait_queue_head_t *q,
				wait_queue_t *wait, int state));
void FASTCALL(finish_wait(wait_queue_head_t *q, wait_queue_t *wait));
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *key);

/*定义并初始化一个等待队列元素*/
#define DEFINE_WAIT(name)						\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= autoremove_wake_function,		\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}

#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
	} while (0)

/**
 * wait_on_bit - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit.
 * For instance, if one were to have waiters on a bitflag, one would
 * call wait_on_bit() in threads waiting for the bit to clear.
 * One uses wait_on_bit() where one is waiting for the bit to clear,
 * but has no intention of setting it.
 */
static inline int wait_on_bit(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit(word, bit, action, mode);
}

/**
 * wait_on_bit_lock - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit
 * when one intends to set it, for instance, trying to lock bitflags.
 * For instance, if one were to have waiters trying to set bitflag
 * and waiting for it to clear before setting it, one would call
 * wait_on_bit() in threads waiting to be able to set the bit.
 * One uses wait_on_bit_lock() where one is waiting for the bit to
 * clear with the intention of setting it, and when done, clearing it.
 */
static inline int wait_on_bit_lock(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
	if (!test_and_set_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_lock(word, bit, action, mode);
}
	
#endif /* __KERNEL__ */

#endif
