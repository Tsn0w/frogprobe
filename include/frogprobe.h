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
 * when register a frogprobe one need the following:
 *  - pre/post_handler: the handler to be called before the function execute
 *  - symbol_name: the symbol of the point want to probe
 *
 * Known limitations:
 * - Doesn't support functions with args on stack
 */

typedef struct frogprobe_s {
    char *trampoline;
    int npages;
    void *address;
    char *symbol_name;
    void *pre_handler;
    void *post_handler;
} frogprobe_t;

// must be the first line of the post_handler (if whish to use)
#define get_return_value(var)                 \
    register unsigned long _dummy asm("rax"); \
    unsigned long var = _dummy

int register_frogprobe(frogprobe_t *fp);
void unregister_frogprobe(frogprobe_t *fp);