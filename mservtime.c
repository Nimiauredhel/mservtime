/* general kernel includes */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/circ_buf.h>
#include <linux/proc_fs.h>

/* networking includes */
#include <linux/if_ether.h>

/* netfilter includes */
#include <linux/netfilter.h>
#include <linux/netfilter_netdev.h>

#define BUFF_LEN (128)
#define ITEM_SIZE (sizeof(struct sk_buff))
#define BUFF_SIZE (BUFF_LEN*ITEM_SIZE)

typedef struct PacketQueue
{
    struct sk_buff circbuff[BUFF_LEN];
    int head;
    int tail;
} PacketQueue_t;

static unsigned int ingress_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void cleanup(void);

static struct task_struct *logger_task_ptr = NULL;
static struct task_struct *echo_task_ptr = NULL;

PacketQueue_t *q_to_log = NULL;
PacketQueue_t *q_to_echo = NULL;

struct nf_hook_ops ingress_hook_ops =
{
    .hook = (nf_hookfn *)ingress_hook,
    .hooknum = NF_NETDEV_INGRESS,
    .pf = NFPROTO_IPV4,
    .priority = 0,
};

static unsigned int ingress_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (skb == NULL)
    {
        return NF_ACCEPT;
    }

    // place incoming skb in queue for the logging task
    if (CIRC_SPACE(q_to_log->head, q_to_log->tail, BUFF_LEN) > 0)
    {
        q_to_log->circbuff[q_to_log->head] = *skb;
        q_to_log->head =  (q_to_log->head + 1) % BUFF_LEN;
    }

    return NF_ACCEPT;
}

static int input_logger_task(void *data)
{
    printk(KERN_INFO "Logger Task START!\n");

    struct sk_buff skb_to_log = {0};
    struct ethhdr *eth_header = NULL;

    while(!kthread_should_stop())
    {
        if (CIRC_CNT(q_to_log->head, q_to_log->tail, BUFF_SIZE) > 0)
        {
            skb_to_log = q_to_log->circbuff[q_to_log->tail];
            q_to_log->tail = (q_to_log->tail + 1) % BUFF_LEN;

            eth_header = eth_hdr(&skb_to_log);

            if (eth_header != NULL)
            {
                    printk(KERN_INFO "Packet caught:\nSource MAC [%X:%X:%X:%X:%X:%X]\nDestination MAC [%X:%X:%X:%X:%X:%X]\n",
                    eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
                    eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5],
                    eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
                    eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
            }

            /*
            while (CIRC_SPACE(q_to_echo->head, q_to_echo->tail, BUFF_SIZE) < 1)
            {
                fsleep(500000);
            }

            q_to_echo->circbuff[q_to_echo->head] = skb_to_log;
            q_to_echo->head =  (q_to_echo->head + 1) % BUFF_LEN;
            */
            fsleep(50000);
        }
        else
        {
            fsleep(100000);
        }
    }

    printk(KERN_INFO "Logger Task STOP!\n");

    return 0;
}

static int input_echo_task(void *data)
{
    printk(KERN_INFO "Echo Task START!\n");

    struct sk_buff skb_to_echo = {0};

    while(!kthread_should_stop())
    {
        fsleep(1000000);
        /*
        if (CIRC_CNT(head, tail, BUFF_LEN) > 0)
        {
            printk("Processed random number [%d].\n", circbuff[tail]);
            tail = (tail + 1) % BUFF_LEN;
        }
        */
    }

    printk(KERN_INFO "Echo Task STOP!\n");

    return 0;
}

static void cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");

    nf_unregister_net_hook(&init_net, &ingress_hook_ops);

    if (logger_task_ptr != NULL)
    {
        printk(KERN_INFO "Stopping logger task.\n");
        kthread_stop(logger_task_ptr);
        logger_task_ptr = NULL;
    }

    if (echo_task_ptr != NULL)
    {
        printk(KERN_INFO "Stopping echo task.\n");
        kthread_stop(echo_task_ptr);
        echo_task_ptr = NULL;
    }

    if (q_to_log != NULL)
    {
        printk(KERN_INFO "Disposing of 'to log' queue.\n");
        kfree(q_to_log);
        q_to_log = NULL;
    }

    if (q_to_echo != NULL)
    {
        printk(KERN_INFO "Disposing of 'to echo' queue.\n");
        kfree(q_to_echo);
        q_to_echo = NULL;
    }

    printk(KERN_INFO "Cleanup complete.\n");
}

static int entry_point(void)
{
    printk(KERN_INFO "Module START!\n");

    q_to_log = kmalloc(sizeof(PacketQueue_t), (GFP_KERNEL | __GFP_ZERO));
    q_to_echo = kmalloc(sizeof(PacketQueue_t), (GFP_KERNEL | __GFP_ZERO));

    if (q_to_log == NULL
        || q_to_echo == NULL)
    {
        printk(KERN_WARNING "Failed to allocate packet queues.\n");
        goto err;
    }

    printk(KERN_INFO "Allocated packet queues.\n");

    logger_task_ptr = kthread_run(input_logger_task, NULL, "LoggerTask");

    if (logger_task_ptr == NULL)
    {
        printk(KERN_WARNING "Failed to start logger task.\n");
        goto err;
    }

    printk(KERN_INFO "Started logger task.\n");

    echo_task_ptr = kthread_run(input_echo_task, NULL, "EchoTask");

    if (echo_task_ptr == NULL)
    {
        printk(KERN_WARNING "Failed to start echo task.\n");
        goto err;
    }

    nf_register_net_hook(&init_net, &ingress_hook_ops);

    printk(KERN_INFO "Started echo task.\n");

    return 0;

err:
    cleanup();
    return 1;
}

static void exit_point(void)
{
    cleanup();
    printk(KERN_INFO "Module END!\n");
}

module_init(entry_point);
module_exit(exit_point);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mickey H.");
MODULE_DESCRIPTION("A simple Linux Kernel Module");
