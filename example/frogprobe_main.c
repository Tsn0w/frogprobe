#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <symbol_extractor.h>
#include <frogprobe.h>

MODULE_LICENSE("GPL");


static void pre_handler(bool wait, const char *fmt)
{
    printk(KERN_INFO"called __request_module pre with fmt: %s!\n", fmt);
}

static void post_handler(bool wait, const char *fmt)
{
    // must be the first line of the post_handler
    get_return_value(orig_rc);

    printk(KERN_INFO"called __request_module pre with fmt: %s! (rc: %lu)\n", fmt, orig_rc);
}

static frogprobe_t __request_module_probe = {
    .symbol_name = "__request_module",
    .pre_handler = (void *)&pre_handler,
    .post_handler = (void *)&post_handler,
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
    printk(KERN_INFO"Run dummy binary to call handlers\n");
    return 0;
}

static void __exit frogprobe_exit(void)
{
    unregister_frogprobe(&__request_module_probe);
    printk(KERN_INFO"unregistered frogprobe on: %s\n", __request_module_probe.symbol_name);
}

module_init(frogprobe_init);
module_exit(frogprobe_exit);
