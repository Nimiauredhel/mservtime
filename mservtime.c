#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int init(void)
{
    printk(KERN_INFO "Module START!\n");
    return 0;
}

static void cleanup(void)
{
    printk(KERN_INFO "Module END!\n");
}

module_init(init);
module_exit(cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mickey H.");
MODULE_DESCRIPTION("A simple Linux Kernel Module");
