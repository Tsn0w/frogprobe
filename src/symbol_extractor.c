#include <linux/printk.h>
#include <linux/version.h>

#include <symbol_extractor.h>

#define DECLARE_SYMBOL(symbol_name) \
        symbol_name ## _t *symbol_name ## _p;

DECLARE_SYMBOL(text_poke);
DECLARE_SYMBOL(set_memory_rox);
DECLARE_SYMBOL(__vmalloc_node_range);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    #define KPROBE_LOOKUP_KALLSYMS 1
    #include <linux/kprobes.h>

    static struct kprobe kallsyms_kprobe = {
        .symbol_name = "kallsyms_lookup_name",
    };

    DECLARE_SYMBOL(kallsyms_lookup_name);
#else
    #error not supported yet...
#endif

#define INIT_SYMBOL(symbol_name)                                                                  \
    do {                                                                                          \
        symbol_name ## _p = (symbol_name ## _t *)kallsyms_lookup_name_p(#symbol_name);            \
        if (!symbol_name ## _p ) {                                                                \
            printk(KERN_ERR"Failed to lookup " #symbol_name);                                     \
            return -1;                                                                            \
        }                                                                                         \
        printk("found symbol " # symbol_name ": 0x%016lx\n", (unsigned long)symbol_name ## _p);   \
    } while(0)


int export_symbols(void)
{
    #ifdef KPROBE_LOOKUP_KALLSYMS
        if (register_kprobe(&kallsyms_kprobe) < 0) {
            printk(KERN_ERR"%s: failed register kallsyms_kprobe\n", __func__);
            return -1;
        }

        kallsyms_lookup_name_p = (kallsyms_lookup_name_t *)kallsyms_kprobe.addr;
        unregister_kprobe(&kallsyms_kprobe);
    #endif

    INIT_SYMBOL(__vmalloc_node_range);
    INIT_SYMBOL(set_memory_rox);
    INIT_SYMBOL(text_poke);

    return 0;
}
