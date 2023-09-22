#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <symbol_extractor.h>
#include <frogprobe.h>

MODULE_LICENSE("GPL");


static void pre_handler(void)
{
    printk(KERN_INFO"called __request_module!\n");
}

static frogprobe_t __request_module_probe = {
    .symbol_name = "__request_module",
    .pre_handler = (void *)&pre_handler,
};

static int __init frogprobe_init(void)
{
    if (export_symbols() < 0) {
        printk(KERN_ERR"export_symbols failed!\n");
        return -1;
    }
    printk(KERN_INFO"exported symbols successfully\n");

    int rc = register_frogprobe(&__request_module_probe);
    if (rc < 0) {
        printk(KERN_ERR"failed to register frogprobe on: %s (%d)\n", __request_module_probe.symbol_name, rc);
        return -1;
    }
    printk(KERN_INFO"init frogprobe successfully!\n");
    return 0;
}

static void __exit frogprobe_exit(void)
{
    unregister_frogprobe(&__request_module_probe);
    printk(KERN_INFO"unregistered frogprobe on: %s\n", __request_module_probe.symbol_name);
}

module_init(frogprobe_init);
module_exit(frogprobe_exit);
