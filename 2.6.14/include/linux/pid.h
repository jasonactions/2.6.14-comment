#ifndef _LINUX_PID_H
#define _LINUX_PID_H

/*4中不同类型的pid哈希*/
enum pid_type
{
	/*进程的PID哈希表*/
	PIDTYPE_PID,
	/*线程组领头线程的PID哈希表*/
	PIDTYPE_TGID,
	/*进程组领头进程的PID*/
	PIDTYPE_PGID,
	/*会话领头进程的PID*/
	PIDTYPE_SID,
	PIDTYPE_MAX
};

/*
 * 嵌入到进程描述符,作为pid哈希桶中散列链表的一个元素，它又通过pid_list链接了线程组的所有线程,ULKP99
 *
 *  pid_hash
 *   +----+
 *   |PID |
 *   +----+            TGID哈希表
 *   |TGID|----------->0 +---+
 *   +----+              |   |
 *   |PGID|              |   |
 *   +----+              |   |
 *   |SID |              |   |
 *   +----+              |   |
 *                       |   |                线程组
 *                    70 +---+              进程描述符         进程描述符
 *                       |   |<-----+       +---------+        +---------+
 *                       +---+      |       |         |        |         |
 *                       |   |      |       | pids[1] |        | pids[1] |
 *                       |   |      |       +---------+        +---------+
 *                   2047+---+      |       | nr=4351 |        | nr=246  |
 *                                  +------>|pid_chain|<------>|pid_chain|
 *                                      +-->| pid_list|        | pid_list|
 *                                      |   +---------+        +---------+
 *                                      |
 *                                      |    进程描述符
 *                                      |   +---------+
 *                                      |   |         |
 *                                      |   | pids[1] |
 *                                      |   +---------+
 *                                      |   | nr=4351 |
 *                                      |   |pid_chain|
 *                                      +-->| pid_list|---+
 *                                          +---------+   |
 *                                                        | 
 *                                          进程描述符    |
 *                                          +---------+   |
 *                                          |         |   |
 *                                          | pids[1] |   |
 *                                          +---------+   |
 *                                          | nr=4351 |   |
 *                                          |pid_chain|   |
 *                                          | pid_list|<--+
 *                                          +---------+
 *                                          
 * 注：1.pid_hash保存四个哈希表的地址
 *     2.以TGID哈希表为例，PID为4351和246的进程描述符的pids[1]通过pid_chain链入同一个哈希链表
 *     3.PID为4351的进程是线程组的领头进程，进程组包含两个进程，通过pid_list链入进程组链表
 */

struct pid
{
	/* Try to keep pid_chain in the same cacheline as nr for find_pid */
	int nr;
	struct hlist_node pid_chain;
	/* list of pids with the same nr, only one of them is in the hash */
	struct list_head pid_list;
};

#define pid_task(elem, type) \
	list_entry(elem, struct task_struct, pids[type].pid_list)

/*
 * attach_pid() and detach_pid() must be called with the tasklist_lock
 * write-held.
 */
extern int FASTCALL(attach_pid(struct task_struct *task, enum pid_type type, int nr));

extern void FASTCALL(detach_pid(struct task_struct *task, enum pid_type));

/*
 * look up a PID in the hash table. Must be called with the tasklist_lock
 * held.
 */
extern struct pid *FASTCALL(find_pid(enum pid_type, int));

extern int alloc_pidmap(void);
extern void FASTCALL(free_pidmap(int));
extern void switch_exec_pids(struct task_struct *leader, struct task_struct *thread);

/*定义do_while循环，作用于哈希表类型为type,pid等于who的pid_list上*/
#define do_each_task_pid(who, type, task)				\
	if ((task = find_task_by_pid_type(type, who))) {		\
		prefetch((task)->pids[type].pid_list.next);		\
		do {

#define while_each_task_pid(who, type, task)				\
		} while (task = pid_task((task)->pids[type].pid_list.next,\
						type),			\
			prefetch((task)->pids[type].pid_list.next),	\
			hlist_unhashed(&(task)->pids[type].pid_chain));	\
	}								\

#endif /* _LINUX_PID_H */
