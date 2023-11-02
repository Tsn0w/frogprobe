#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <symbol_extractor.h>
#include <frogprobe.h>

MODULE_LICENSE("GPL");

static int __init frogprobe_init(void)
{
    if (export_symbols() < 0) {
        printk(KERN_ERR"export_symbols failed!\n");
        return -1;
    }

    printk(KERN_DEBUG"frogprobes are ready to use!\n");
    return 0;
}

static void __exit frogprobe_exit(void)
{
    /*
     * frogprobe can be removed when no more symbols are used, meaning no other
     * LKM uses it's exported_symbols (un/register_frogprobe)
     */
    printk(KERN_DEBUG"unloaded frogrobes!\n");
}

module_init(frogprobe_init);
module_exit(frogprobe_exit);
