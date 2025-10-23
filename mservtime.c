#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/circ_buf.h>

#define BUFF_LEN (256)
#define BUFF_SIZE (sizeof(int)*BUFF_LEN)

static struct task_struct *listener_task_ptr = NULL;
static struct task_struct *processing_task_ptr = NULL;

static int *circbuff = NULL;
static int head = 0;
static int tail = 0;

static int input_processing_task(void *data)
{
    printk(KERN_INFO "Processing Task START!\n");

    while(!kthread_should_stop())
    {
        fsleep(1000000);
        if (CIRC_CNT(head, tail, BUFF_LEN) > 0)
        {
            printk("Processed random number [%d].\n", circbuff[tail]);
            tail = (tail + 1) % BUFF_LEN;
        }
    }

    printk(KERN_INFO "Processing Task STOP!\n");

    return 0;
}

static int input_listener_task(void *data)
{
    printk(KERN_INFO "Listener Task START!\n");

    while(!kthread_should_stop())
    {
        fsleep(500000);
        if (CIRC_SPACE(head, tail, BUFF_LEN) > 0)
        {
            get_random_bytes(circbuff+head, sizeof(int));
            printk("Entered random number [%d].\n", circbuff[head]);
            head = (head + 1) % BUFF_LEN;
        }
    }

    printk(KERN_INFO "Listener Task STOP!\n");

    return 0;
}

static int init(void)
{
    printk(KERN_INFO "Module START!\n");
    circbuff = kmalloc(BUFF_SIZE, (GFP_KERNEL | __GFP_ZERO));
    if (circbuff == NULL)
    {
        printk(KERN_WARNING "Failed to allocate buffer.\n");
        return 1;
    }
    listener_task_ptr = kthread_run(input_processing_task, NULL, "ListenerTask");
    processing_task_ptr = kthread_run(input_listener_task, NULL, "ProcessingTask");
    return 0;
}

static void cleanup(void)
{
    if (listener_task_ptr != NULL)
    {
        kthread_stop(listener_task_ptr);
    }
    if (processing_task_ptr != NULL)
    {
        kthread_stop(processing_task_ptr);
    }
    kfree(circbuff);
    printk(KERN_INFO "Module END!\n");
}

module_init(init);
module_exit(cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mickey H.");
MODULE_DESCRIPTION("A simple Linux Kernel Module");
