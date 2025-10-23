#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
    printk(KERN_INFO "Module START!\n");
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Module END!\n");
}

MODULE_LICENSE("GPL");
