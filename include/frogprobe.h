#pragma once
/*
 * frogprobe is I/S for hooking kernel functions just like kprobe with the ability to
 * sleep in it, currently kprobe are working with percpu variables (current_kprobe).
 * This type of probe are aiming to solve this issue.
 * Both pre and post handlers should have the same functions signautre (or at least
 * same number of params you wish to inspect).
 *
 * Beside post & pre handlers, there is a way to fully replace the symbol by returning
 * the address want to run (in the pre_handler), it will cause the address to be
 * executed instead of the original functions in the order of:
 *  pre_handler -> address returned at pre_handler -> post_handler
 *
 * Multiple frogprobes:
 * Currently supported only at pre_handler.
 * pre handlers are called in the order they were registered, but if one wish to
 * change the flow (return != 0), the follow will not run.
 *
 * when register a frogprobe one need the following:
 *  - pre/post_handler: the handler to be called before the function execute
 *  - symbol_name: the symbol of the point want to probe
 *
 * Known limitations:
 * - Doesn't support functions with args on stack
 */

typedef unsigned long (frogporbe_handler_t)(unsigned long rdi, unsigned long rsi,
                                            unsigned long rdx, unsigned long rcx,
                                            unsigned long r8, unsigned long r9);

typedef struct frogprobe_s {
    char *trampoline;
    int npages;
    void *address;
    char *symbol_name;
    frogporbe_handler_t *pre_handler;
    frogporbe_handler_t *post_handler;
    struct hlist_node hlist;
    struct list_head list;
} frogprobe_t;

typedef struct frogprobe_regs_s {
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
} frogprobe_regs_t;

// must be the first line of the post_handler (if whish to use)
#define get_return_value(var)                 \
    register unsigned long _dummy asm("rax"); \
    unsigned long var = _dummy

int register_frogprobe(frogprobe_t *fp);
void unregister_frogprobe(frogprobe_t *fp);