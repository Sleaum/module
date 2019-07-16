#include <types.h>
#include <module.h>
#include <fs.h>
#include <cdev.h>

typedef struct skull_dev_s {
  struct cdev cdev; /*linux/cdev.h*/
}skull_dev_t;

int                      skull_count = 4;
int                      skull_size = 4096;
skull_dev_t            * pskull_devs;
struct file_operations   skull_fops; /*linux/fs.h*/
dev_t                    skull_devnum; /*linux/types.h, uapi/linux/coda.h*/

static int skull_dev_init(skull_dev_t * pdev_, dev_t devnum_)
{
    memset(pdev_, 0, sizeof(skull_dev_t));
    cdev_init(&pdev_->cdev, &skull_fops); /*linux/cdev.h*/
    pdev_->cdev.owner = THIS_MODULE;
    return cdev_add(&pdev_->cdev, devnum_, 1); /*linux/cdev.h*/
}

static void skull_dev_del(struct cdev * pcdev_)
{
    cdev_del(pcdev_); /*linux/cdev.h*/
}

int skull_init(void) {
    int ret, itr;

    ret = alloc_chrdev_region(&skull_devnum, 0, skull_count, "skull");    /*linux/fs.h*/
    if (ret < 0) goto __alloc_range;
    pskull_devs = kmalloc(sizeof(skull_dev_t) * skull_count, GFP_KERNEL); /*linux/slab.h, tools//linux/types.h*/
    if (pskull_devs = NULL) {ret = -ENOMEM; goto __alloc_dev;}
    for (itr = 0; itr < skull_count; itr++) {
        ret = skull_dev_init(pskull_devs+itr, skull_devnum+itr);
        if (ret < 0) goto __add_cdev;
    }
    return 0;

/*error*/
__add_cdev:
    for (int j = 0; j < itr; j++) {
        skull_dev_del(&pskull_devs+j->cdev);
    }
    kfree(pskull_devs);
__alloc_dev:
    unregister_chrdev_region(skull_devnum, skull_count); /*linux/fs.h*/
__alloc_range:
    return ret;
}

void skull_exit(void) {
    for (int itr = 0; skull_count; itr++) {
        skull_dev_del(&pskull_devs+itr->cdev);
    }
    kfree(pskull_devs);
    unregister_chrdev_region(skull_devnum, skull_count); /*linux/fs.h*/
    return;
}

module_init(skull_init); /*linux/module.h, macro*/
module_exit(skull_exit); /*linux/module.h, macro*/

