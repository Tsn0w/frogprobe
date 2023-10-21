#pragma once

#include <linux/refcount.h>

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
 * post and pre handlers are called in the order they were registered,
 * but if one wish to change the flow (return != 0), the next pre handlers will
 * not run. (only at pre-handlers, post_handlers runs always)
 *
 * when register a frogprobe one need the following:
 *  - pre/post_handler: the handler to be called before the function execute
 *  - symbol_name: the symbol of the point want to probe
 *
 * Known limitations:
 * - Doesn't support functions with args on stack
 * - Doesn't work with kprobe
 */

typedef unsigned long (frogprobe_pre_handler_t)(unsigned long rdi, unsigned long rsi,
                                                unsigned long rdx, unsigned long rcx,
                                                unsigned long r8, unsigned long r9);

typedef unsigned long (frogprobe_post_handler_t)(unsigned long rc, unsigned long rdi,
                                                unsigned long rsi, unsigned long rdx,
                                                unsigned long rcx, unsigned long r8,
                                                unsigned long r9);
typedef struct frogprobe_s {
    char *trampoline;
    int npages;
    void *address;
    char *symbol_name;
    frogprobe_pre_handler_t *pre_handler;
    frogprobe_post_handler_t *post_handler;
    struct hlist_node hlist;
    struct list_head list;
    refcount_t refcnt;
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

int register_frogprobe(frogprobe_t *fp);
void unregister_frogprobe(frogprobe_t *fp);