#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <linux/config.h>
#include <linux/kernel.h>
#include <asm/segment.h>
#include <asm/cpufeature.h>
#include <linux/bitops.h> /* for LOCK_PREFIX */

#ifdef __KERNEL__

struct task_struct;	/* one of the stranger aspects of C forward declarations.. */
extern struct task_struct * FASTCALL(__switch_to(struct task_struct *prev, struct task_struct *next));

/*
 * 执行进程上下文切换
 * @prev: 被暂停执行的进程的描述符指针,假设为进程A
 * @next: 将激活执行的进程的描述符指针,假设为进程B
 * @last: 为刚被替换的进程的描述符指针,假设为进程A
 *
 * 注：1.pop/push这样的操作，都是对esp所指向的堆栈进行的，这些操作同时也会改变esp本身，
 *       除此之外，其它关于变量的引用，都是对ebp所指向的堆栈进行的。
 *     2.refs:https://www.cnblogs.com/visayafan/archive/2011/12/10/2283660.html
 */
#define switch_to(prev,next,last) do {					\
	unsigned long esi,edi;						\
	/*
	 * 将ebp_A入进程A栈
	 * 注：ebp是栈底指针，它确定了当前变量空间属于哪个进程
	 */
	asm volatile("pushl %%ebp\n\t"					\
		     /*
		      * 将esp_A寄存器内容保存到prev->thread.esp
		      * 注：%0表示第0个表达式（"()"中为一个表达式）
		      */
		     "movl %%esp,%0\n\t"	/* save ESP */		\
		     
		     /*
		      * 切换为进程B的栈，将next->thread.esp恢复到esp寄存器
		      * 注：现在的ebp仍然指向进程A的内核堆栈，所以所有局部变量仍然是进程A栈中的局部变量
		      */
		     "movl %5,%%esp\n\t"	/* restore ESP */	\
		     /*将标记为1的地址保存到prev->thread.eip,它将作为进程A再次执行时的地址*/
		     "movl $1f,%1\n\t"		/* save EIP */		\
		     /*
		      * 将next->thread.eip入进程B栈,__switch_to中ret将用此恢复eip寄存器
		      * 如果之前B也被switch_to出去过，那么next->thread.eip为下面这个1的标号
		      * 但如果进程B刚刚被创建，之前没有被switch_to出去过，那么next->thread.eip为ret_ftom_fork（参看copy_thread()函数）
		      */
		     "pushl %6\n\t"		/* restore EIP */	\
		     /*
		      * 如果之前进程B也被switch_to出去过，那么__switch_to返回后eip被恢复为下面这个1的标号，
		      * 但如果进程B刚刚被创建，之前没有被switch_to出去过，__switch_to返回后eip被恢复为ret_ftom_fork（参看copy_thread()函数）。
		      * 这就是这里为什么不用call __switch_to而用jmp，因为call会导致自动把下面这句话的地址(也就是1:)压栈，
		      * 然后__switch_to()就必然只能ret到这里，而无法根据需要ret到ret_from_fork。
		      * 注：另外请注意，这里__switch_to()返回时，将返回值prev_A又写入了%eax，
		      * 这就使得在switch_to宏里面eax寄存器始终保存的是prev_A的内容，或者，更准确的说，是指向A进程描述符的“指针”。
		      * 这是有用的，下面将会看到
		      */
		     "jmp __switch_to\n"				\
		     
		     "1:\t"						\
		     /*
		      * 恢复ebp_next的值到ebp寄存器
		      * 如果从__switch_to()返回后从这里继续运行，那么说明在此之前B肯定被switch_to调出过，
		      * 因此此前肯定备份了ebp_next，这里执行恢复操作
		      * 这时候ebp已经指向了B的内核堆栈，所以上面的prev,next等局部变量已经不再是A进程堆栈中的了，
		      * 而是B进程堆栈中的(B上次被切换出去之前也有这两个变量，所以代表着B堆栈中prev、next的值了)
		      * 而在B上次被切换出去之前，prev保存的是B进程的描述符地址
		      * 如果这个时候就结束switch_to的话，在后面的代码中（即 context_switch()函数中switch_to之后的代码）的prev变量是指向B进程的，
		      * 因此，进程B就不知道是从哪个进程切换回来的。而从context_switch()中switch_to之后的代码中，
		      * 我们看到finish_task_switch(this_rq(), prev)中需要知道之前是从哪个进程切换过来的，
		      * 因此，我们必须想办法保存A进程的描述符到B的堆栈中，这就是last的作用。
		      *
		      * 注：从此之后才是完全运行在next上下文（包括esp,ebp等都是next进程的）
		      */
		     "popl %%ebp\n\t"					\
		     
		     /*
		      * ===输出section
		      */
		     /* m表示内存变量,将内存内容输出到prev->thread.esp和prev->thread.eip*/
		     :"=m" (prev->thread.esp),"=m" (prev->thread.eip),	\
		     /*
		      * 表示把eax寄存器输出到变量last;esi寄存器输出到变量esi;edi寄存器输出到变量edi
		      * 注：将eax写入last，以在B的堆栈中保存正确的prev信息,即指示B是由哪个进程切换过来，供context_switch后续代码使用
		      *     这里面的last实质上就是prev，因此在switch_to宏执行完之后，prev_B就是正确的A的进程描述符了
		      *     last的作用相当于把进程A堆栈中的A进程描述符地址复制到了进程B的堆栈中
		      */
		      "=a" (last),"=S" (esi),"=D" (edi)			\
		     
                     /*
		      * ===输入section
		      */
		     /*next->thread.esp和next->thread.eip输入到内存*/
		     :"m" (next->thread.esp),"m" (next->thread.eip),	\
		     /*
		      * prev输入到eax寄存器，next变量输入到edx寄存器
		      * 注：此处的2表示与表达式2即(last)使用相同的寄存器即eax
		      */
		      "2" (prev), "d" (next));				\
} while (0)

#define _set_base(addr,base) do { unsigned long __pr; \
__asm__ __volatile__ ("movw %%dx,%1\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %%dl,%2\n\t" \
	"movb %%dh,%3" \
	:"=&d" (__pr) \
	:"m" (*((addr)+2)), \
	 "m" (*((addr)+4)), \
	 "m" (*((addr)+7)), \
         "0" (base) \
        ); } while(0)

#define _set_limit(addr,limit) do { unsigned long __lr; \
__asm__ __volatile__ ("movw %%dx,%1\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %2,%%dh\n\t" \
	"andb $0xf0,%%dh\n\t" \
	"orb %%dh,%%dl\n\t" \
	"movb %%dl,%2" \
	:"=&d" (__lr) \
	:"m" (*(addr)), \
	 "m" (*((addr)+6)), \
	 "0" (limit) \
        ); } while(0)

#define set_base(ldt,base) _set_base( ((char *)&(ldt)) , (base) )
#define set_limit(ldt,limit) _set_limit( ((char *)&(ldt)) , ((limit)-1)>>12 )

static inline unsigned long _get_base(char * addr)
{
	unsigned long __base;
	__asm__("movb %3,%%dh\n\t"
		"movb %2,%%dl\n\t"
		"shll $16,%%edx\n\t"
		"movw %1,%%dx"
		:"=&d" (__base)
		:"m" (*((addr)+2)),
		 "m" (*((addr)+4)),
		 "m" (*((addr)+7)));
	return __base;
}

#define get_base(ldt) _get_base( ((char *)&(ldt)) )

/*
 * Load a segment. Fall back on loading the zero
 * segment if something goes wrong..
 */
#define loadsegment(seg,value)			\
	asm volatile("\n"			\
		"1:\t"				\
		"mov %0,%%" #seg "\n"		\
		"2:\n"				\
		".section .fixup,\"ax\"\n"	\
		"3:\t"				\
		"pushl $0\n\t"			\
		"popl %%" #seg "\n\t"		\
		"jmp 2b\n"			\
		".previous\n"			\
		".section __ex_table,\"a\"\n\t"	\
		".align 4\n\t"			\
		".long 1b,3b\n"			\
		".previous"			\
		: :"rm" (value))

/*
 * Save a segment register away
 */
#define savesegment(seg, value) \
	asm volatile("mov %%" #seg ",%0":"=rm" (value))

/*
 * Clear and set 'TS' bit respectively
 */
#define clts() __asm__ __volatile__ ("clts")
#define read_cr0() ({ \
	unsigned int __dummy; \
	__asm__ __volatile__( \
		"movl %%cr0,%0\n\t" \
		:"=r" (__dummy)); \
	__dummy; \
})
#define write_cr0(x) \
	__asm__ __volatile__("movl %0,%%cr0": :"r" (x));

#define read_cr2() ({ \
	unsigned int __dummy; \
	__asm__ __volatile__( \
		"movl %%cr2,%0\n\t" \
		:"=r" (__dummy)); \
	__dummy; \
})
#define write_cr2(x) \
	__asm__ __volatile__("movl %0,%%cr2": :"r" (x));

#define read_cr3() ({ \
	unsigned int __dummy; \
	__asm__ ( \
		"movl %%cr3,%0\n\t" \
		:"=r" (__dummy)); \
	__dummy; \
})
#define write_cr3(x) \
	__asm__ __volatile__("movl %0,%%cr3": :"r" (x));

#define read_cr4() ({ \
	unsigned int __dummy; \
	__asm__( \
		"movl %%cr4,%0\n\t" \
		:"=r" (__dummy)); \
	__dummy; \
})
#define write_cr4(x) \
	__asm__ __volatile__("movl %0,%%cr4": :"r" (x));
#define stts() write_cr0(8 | read_cr0())

#endif	/* __KERNEL__ */

#define wbinvd() \
	__asm__ __volatile__ ("wbinvd": : :"memory");

static inline unsigned long get_limit(unsigned long segment)
{
	unsigned long __limit;
	__asm__("lsll %1,%0"
		:"=r" (__limit):"r" (segment));
	return __limit+1;
}

#define nop() __asm__ __volatile__ ("nop")

#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

#define tas(ptr) (xchg((ptr),1))

struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))


#ifdef CONFIG_X86_CMPXCHG64

/*
 * The semantics of XCHGCMP8B are a bit strange, this is why
 * there is a loop and the loading of %%eax and %%edx has to
 * be inside. This inlines well in most cases, the cached
 * cost is around ~38 cycles. (in the future we might want
 * to do an SIMD/3DNOW!/MMX/FPU 64-bit store here, but that
 * might have an implicit FPU-save as a cost, so it's not
 * clear which path to go.)
 *
 * cmpxchg8b must be used with the lock prefix here to allow
 * the instruction to be executed atomically, see page 3-102
 * of the instruction set reference 24319102.pdf. We need
 * the reader side to see the coherent 64bit value.
 */
static inline void __set_64bit (unsigned long long * ptr,
		unsigned int low, unsigned int high)
{
	__asm__ __volatile__ (
		"\n1:\t"
		"movl (%0), %%eax\n\t"
		"movl 4(%0), %%edx\n\t"
		"lock cmpxchg8b (%0)\n\t"
		"jnz 1b"
		: /* no outputs */
		:	"D"(ptr),
			"b"(low),
			"c"(high)
		:	"ax","dx","memory");
}

static inline void __set_64bit_constant (unsigned long long *ptr,
						 unsigned long long value)
{
	__set_64bit(ptr,(unsigned int)(value), (unsigned int)((value)>>32ULL));
}
#define ll_low(x)	*(((unsigned int*)&(x))+0)
#define ll_high(x)	*(((unsigned int*)&(x))+1)

static inline void __set_64bit_var (unsigned long long *ptr,
			 unsigned long long value)
{
	__set_64bit(ptr,ll_low(value), ll_high(value));
}

#define set_64bit(ptr,value) \
(__builtin_constant_p(value) ? \
 __set_64bit_constant(ptr, value) : \
 __set_64bit_var(ptr, value) )

#define _set_64bit(ptr,value) \
(__builtin_constant_p(value) ? \
 __set_64bit(ptr, (unsigned int)(value), (unsigned int)((value)>>32ULL) ) : \
 __set_64bit(ptr, ll_low(value), ll_high(value)) )

#endif

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
	switch (size) {
		case 1:
			__asm__ __volatile__("xchgb %b0,%1"
				:"=q" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 2:
			__asm__ __volatile__("xchgw %w0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
		case 4:
			__asm__ __volatile__("xchgl %0,%1"
				:"=r" (x)
				:"m" (*__xg(ptr)), "0" (x)
				:"memory");
			break;
	}
	return x;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

#ifdef CONFIG_X86_CMPXCHG
#define __HAVE_ARCH_CMPXCHG 1

static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
				      unsigned long new, int size)
{
	unsigned long prev;
	switch (size) {
	case 1:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgb %b1,%2"
				     : "=a"(prev)
				     : "q"(new), "m"(*__xg(ptr)), "0"(old)
				     : "memory");
		return prev;
	case 2:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgw %w1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg(ptr)), "0"(old)
				     : "memory");
		return prev;
	case 4:
		__asm__ __volatile__(LOCK_PREFIX "cmpxchgl %1,%2"
				     : "=a"(prev)
				     : "r"(new), "m"(*__xg(ptr)), "0"(old)
				     : "memory");
		return prev;
	}
	return old;
}

#define cmpxchg(ptr,o,n)\
	((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)(o),\
					(unsigned long)(n),sizeof(*(ptr))))

#endif

#ifdef CONFIG_X86_CMPXCHG64

static inline unsigned long long __cmpxchg64(volatile void *ptr, unsigned long long old,
				      unsigned long long new)
{
	unsigned long long prev;
	__asm__ __volatile__(LOCK_PREFIX "cmpxchg8b %3"
			     : "=A"(prev)
			     : "b"((unsigned long)new),
			       "c"((unsigned long)(new >> 32)),
			       "m"(*__xg(ptr)),
			       "0"(old)
			     : "memory");
	return prev;
}

#define cmpxchg64(ptr,o,n)\
	((__typeof__(*(ptr)))__cmpxchg64((ptr),(unsigned long long)(o),\
					(unsigned long long)(n)))

#endif
    
#ifdef __KERNEL__
struct alt_instr { 
	__u8 *instr; 		/* original instruction */
	__u8 *replacement;
	__u8  cpuid;		/* cpuid bit set for replacement */
	__u8  instrlen;		/* length of original instruction */
	__u8  replacementlen; 	/* length of new instruction, <= instrlen */ 
	__u8  pad;
}; 
#endif

/* 
 * Alternative instructions for different CPU types or capabilities.
 * 
 * This allows to use optimized instructions even on generic binary
 * kernels.
 * 
 * length of oldinstr must be longer or equal the length of newinstr
 * It can be padded with nops as needed.
 * 
 * For non barrier like inlines please define new variants
 * without volatile and memory clobber.
 */
#define alternative(oldinstr, newinstr, feature) 	\
	asm volatile ("661:\n\t" oldinstr "\n662:\n" 		     \
		      ".section .altinstructions,\"a\"\n"     	     \
		      "  .align 4\n"				       \
		      "  .long 661b\n"            /* label */          \
		      "  .long 663f\n"		  /* new instruction */ 	\
		      "  .byte %c0\n"             /* feature bit */    \
		      "  .byte 662b-661b\n"       /* sourcelen */      \
		      "  .byte 664f-663f\n"       /* replacementlen */ \
		      ".previous\n"						\
		      ".section .altinstr_replacement,\"ax\"\n"			\
		      "663:\n\t" newinstr "\n664:\n"   /* replacement */    \
		      ".previous" :: "i" (feature) : "memory")  

/*
 * Alternative inline assembly with input.
 * 
 * Pecularities:
 * No memory clobber here. 
 * Argument numbers start with 1.
 * Best is to use constraints that are fixed size (like (%1) ... "r")
 * If you use variable sized constraints like "m" or "g" in the 
 * replacement maake sure to pad to the worst case length.
 */
#define alternative_input(oldinstr, newinstr, feature, input...)		\
	asm volatile ("661:\n\t" oldinstr "\n662:\n"				\
		      ".section .altinstructions,\"a\"\n"			\
		      "  .align 4\n"						\
		      "  .long 661b\n"            /* label */			\
		      "  .long 663f\n"		  /* new instruction */ 	\
		      "  .byte %c0\n"             /* feature bit */		\
		      "  .byte 662b-661b\n"       /* sourcelen */		\
		      "  .byte 664f-663f\n"       /* replacementlen */ 		\
		      ".previous\n"						\
		      ".section .altinstr_replacement,\"ax\"\n"			\
		      "663:\n\t" newinstr "\n664:\n"   /* replacement */ 	\
		      ".previous" :: "i" (feature), ##input)

/*
 * Force strict CPU ordering.
 * And yes, this is required on UP too when we're talking
 * to devices.
 *
 * For now, "wmb()" doesn't actually do anything, as all
 * Intel CPU's follow what Intel calls a *Processor Order*,
 * in which all writes are seen in the program order even
 * outside the CPU.
 *
 * I expect future Intel CPU's to have a weaker ordering,
 * but I'd also expect them to finally get their act together
 * and add some real memory barriers if so.
 *
 * Some non intel clones support out of order store. wmb() ceases to be a
 * nop for these.
 */
 

/* 
 * Actually only lfence would be needed for mb() because all stores done 
 * by the kernel should be already ordered. But keep a full barrier for now. 
 */

#define mb() alternative("lock; addl $0,0(%%esp)", "mfence", X86_FEATURE_XMM2)
#define rmb() alternative("lock; addl $0,0(%%esp)", "lfence", X86_FEATURE_XMM2)

/**
 * read_barrier_depends - Flush all pending reads that subsequents reads
 * depend on.
 *
 * No data-dependent reads from memory-like regions are ever reordered
 * over this barrier.  All reads preceding this primitive are guaranteed
 * to access memory (but not necessarily other CPUs' caches) before any
 * reads following this primitive that depend on the data return by
 * any of the preceding reads.  This primitive is much lighter weight than
 * rmb() on most CPUs, and is never heavier weight than is
 * rmb().
 *
 * These ordering constraints are respected by both the local CPU
 * and the compiler.
 *
 * Ordering is not guaranteed by anything other than these primitives,
 * not even by data dependencies.  See the documentation for
 * memory_barrier() for examples and URLs to more information.
 *
 * For example, the following code would force ordering (the initial
 * value of "a" is zero, "b" is one, and "p" is "&a"):
 *
 * <programlisting>
 *	CPU 0				CPU 1
 *
 *	b = 2;
 *	memory_barrier();
 *	p = &b;				q = p;
 *					read_barrier_depends();
 *					d = *q;
 * </programlisting>
 *
 * because the read of "*q" depends on the read of "p" and these
 * two reads are separated by a read_barrier_depends().  However,
 * the following code, with the same initial values for "a" and "b":
 *
 * <programlisting>
 *	CPU 0				CPU 1
 *
 *	a = 2;
 *	memory_barrier();
 *	b = 3;				y = b;
 *					read_barrier_depends();
 *					x = a;
 * </programlisting>
 *
 * does not enforce ordering, since there is no data dependency between
 * the read of "a" and the read of "b".  Therefore, on some CPUs, such
 * as Alpha, "y" could be set to 3 and "x" to 0.  Use rmb()
 * in cases like thiswhere there are no data dependencies.
 **/

#define read_barrier_depends()	do { } while(0)

#ifdef CONFIG_X86_OOSTORE
/* Actually there are no OOO store capable CPUs for now that do SSE, 
   but make it already an possibility. */
#define wmb() alternative("lock; addl $0,0(%%esp)", "sfence", X86_FEATURE_XMM)
#else
#define wmb()	__asm__ __volatile__ ("": : :"memory")
#endif

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#define smp_read_barrier_depends()	read_barrier_depends()
#define set_mb(var, value) do { xchg(&var, value); } while (0)
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#define smp_read_barrier_depends()	do { } while(0)
#define set_mb(var, value) do { var = value; barrier(); } while (0)
#endif

#define set_wmb(var, value) do { var = value; wmb(); } while (0)

/* interrupt control.. */
#define local_save_flags(x)	do { typecheck(unsigned long,x); __asm__ __volatile__("pushfl ; popl %0":"=g" (x): /* no input */); } while (0)
#define local_irq_restore(x) 	do { typecheck(unsigned long,x); __asm__ __volatile__("pushl %0 ; popfl": /* no output */ :"g" (x):"memory", "cc"); } while (0)
#define local_irq_disable() 	__asm__ __volatile__("cli": : :"memory")
#define local_irq_enable()	__asm__ __volatile__("sti": : :"memory")
/* used in the idle loop; sti takes one instruction cycle to complete */
#define safe_halt()		__asm__ __volatile__("sti; hlt": : :"memory")
/* used when interrupts are already enabled or to shutdown the processor */
#define halt()			__asm__ __volatile__("hlt": : :"memory")

#define irqs_disabled()			\
({					\
	unsigned long flags;		\
	local_save_flags(flags);	\
	!(flags & (1<<9));		\
})

/* For spinlocks etc */
#define local_irq_save(x)	__asm__ __volatile__("pushfl ; popl %0 ; cli":"=g" (x): /* no input */ :"memory")

/*
 * disable hlt during certain critical i/o operations
 */
#define HAVE_DISABLE_HLT
void disable_hlt(void);
void enable_hlt(void);

extern int es7000_plat;
void cpu_idle_wait(void);

extern unsigned long arch_align_stack(unsigned long sp);

#endif
