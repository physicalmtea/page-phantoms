#include <asm/page.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pagemap.h> // Header for pagecache_get_page
#include <linux/stat.h>
#include <linux/uaccess.h>

#define DEV_NAME "get_inodes_helper"
#define CLASS_NAME "gpa_tools"

#define GET_GPA_INFO _IOR('g', 1, struct gpa_info_req)

struct gpa_info_req {
	uint64_t inode_gpa;
	uint64_t data_page_gpa;
	char path[128];
};

static int major_num;
static struct class *gpa_class;
static struct device *gpa_dev;
static struct cdev gpa_cdev;

static long gpa_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct gpa_info_req req;
	struct path p;
	struct inode *inode;
	struct address_space *mapping;
	struct page *page;
	pgoff_t index = 0;
	long ret = 0;

	if (cmd != GET_GPA_INFO)
		return -EINVAL;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.inode_gpa = 0;
	req.data_page_gpa = 0;

	if (kern_path(req.path, LOOKUP_FOLLOW, &p) == 0) {
		inode = p.dentry->d_inode;
		req.inode_gpa = slow_virt_to_phys((void *)inode);

		mapping = inode->i_mapping;
		page = pagecache_get_page(mapping, index, 0, 0);
		if (page) {
			req.data_page_gpa = PFN_PHYS(page_to_pfn(page));
			put_page(page);
		} else {
			// pr_warn("%s: Data page 0 for '%s' not in cache. 'cat' file in L2.\n", DEV_NAME, req.path);
		}

		path_put(&p);
		ret = 0;
	} else {
		pr_warn("%s: Path '%s' not found.\n", DEV_NAME, req.path);
		ret = -ENOENT;
	}

	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		ret = -EFAULT;

	return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = gpa_ioctl,
};

static int __init get_inodes_helper_init(void)
{
	int ret;
	dev_t dev;

	ret = alloc_chrdev_region(&dev, 0, 1, DEV_NAME);
	if (ret < 0) {
		pr_alert("%s: Failed alloc major num.\n", DEV_NAME);
		return ret;
	}
	major_num = MAJOR(dev);
	pr_info("%s: Registered with major num %d.\n", DEV_NAME, major_num);

	gpa_class = class_create(CLASS_NAME);
	if (IS_ERR(gpa_class)) {
		unregister_chrdev_region(MKDEV(major_num, 0), 1);
		pr_alert("%s: Failed reg dev class.\n", DEV_NAME);
		return PTR_ERR(gpa_class);
	}
	pr_info("%s: Device class registered.\n", DEV_NAME);

	gpa_dev = device_create(gpa_class, NULL, MKDEV(major_num, 0), NULL, DEV_NAME);
	if (IS_ERR(gpa_dev)) {
		class_destroy(gpa_class);
		unregister_chrdev_region(MKDEV(major_num, 0), 1);
		pr_alert("%s: Failed create dev.\n", DEV_NAME);
		return PTR_ERR(gpa_dev);
	}

	cdev_init(&gpa_cdev, &fops);
	gpa_cdev.owner = THIS_MODULE;
	ret = cdev_add(&gpa_cdev, MKDEV(major_num, 0), 1);
	if (ret < 0) {
		device_destroy(gpa_class, MKDEV(major_num, 0));
		class_destroy(gpa_class);
		unregister_chrdev_region(MKDEV(major_num, 0), 1);
		pr_alert("%s: Failed add cdev.\n", DEV_NAME);
		return ret;
	}

	pr_info("%s: Device created at /dev/%s.\n", DEV_NAME, DEV_NAME);
	return 0;
}

static void __exit get_inodes_helper_exit(void)
{
	cdev_del(&gpa_cdev);
	device_destroy(gpa_class, MKDEV(major_num, 0));
	class_destroy(gpa_class);
	unregister_chrdev_region(MKDEV(major_num, 0), 1);
	pr_info("%s: Module unloaded.\n", DEV_NAME);
}

module_init(get_inodes_helper_init);
module_exit(get_inodes_helper_exit);

MODULE_LICENSE("GPL");
