#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <frogprobe.h>

MODULE_LICENSE("GPL");

static int function_replacement(void)
{
    printk("Function '__request_module' replaced with %s", __FUNCTION__);
    return -1;
}

static void *pre_handler(bool wait, const char *fmt)
{
    printk(KERN_INFO"called __request_module pre with fmt: %s!\n", fmt);
    return (void *)&function_replacement;
}

// type of rc should be the type return by the function
// https://elixir.bootlin.com/linux/latest/source/kernel/module/kmod.c#L132
static void post_handler(int rc, bool wait, const char *fmt)
{
    printk(KERN_INFO"called __request_module post with fmt: %s! (rc: %d)\n", fmt, rc);
}

static frogprobe_t __request_module_probe = {
    .symbol_name = "__request_module",
    .pre_handler = (void *)&pre_handler,
    .post_handler = (void *)&post_handler,
};

static int __init frogprobe_user_init(void)
{
    int rc = register_frogprobe(&__request_module_probe);
    if (rc < 0) {
        printk(KERN_ERR"failed to register frogprobe on: %s (%d)\n", __request_module_probe.symbol_name, rc);
        return -1;
    }
    printk(KERN_INFO"registered frogprobe on __request_module!\n");
    return 0;
}

static void __exit frogprobe_user_exit(void)
{
    unregister_frogprobe(&__request_module_probe);
    printk(KERN_INFO"unregistered frogprobe on: %s\n", __request_module_probe.symbol_name);
}

module_init(frogprobe_user_init);
module_exit(frogprobe_user_exit);
