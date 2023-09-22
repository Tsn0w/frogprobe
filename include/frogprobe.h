#pragma once
/*
 * frogprobe is I/S for hooking kernel functions just like kprobe with the ability to
 * sleep in it, currently kprobe are working with percpu variables (current_kprobe).
 * This type of probe are aiming to solve this issue.
 *
 * when register a frogprobe one need the following:
 *  - pre_handler: the handler to be called before the function execute
 *  - symbol_name: the symbol of the point want to probe
 */

typedef struct frogprobe_s {
    char *trampoline;
    int npages;
    void *address;
    char *symbol_name;
    void *pre_handler;
} frogprobe_t;

int register_frogprobe(frogprobe_t *fp);
void unregister_frogprobe(frogprobe_t *fp);