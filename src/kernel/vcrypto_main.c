#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include "vcrypto_ioctl.h"

struct vcrypto_data {
	char hw_buffer[1024];
	struct mutex lock;
	struct miscdevice misc_dev;

	int current_key;
	int is_open;
};

static struct vcrypto_data *vcrypto_chip;

static int vcrypto_open(struct inode *inodep, struct file *filep)
{
	struct miscdevice *misc = filep->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	mutex_lock(&chip->lock);

	if (chip->is_open) {
		mutex_unlock(&chip->lock);
		printk(KERN_INFO "vCrypto: \n");
		return -EBUSY;
	}

	chip->is_open = 1;
	mutex_unlock(&chip->lock);

	printk(KERN_INFO "vCrypto: \n");
	return 0;
}

static int vcrypto_release(struct inode *inodep, struct file *filep)
{
	struct miscdevice *misc = filep->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	mutex_lock(&chip->lock);
	chip->is_open = 0;
	mutex_unlock(&chip->lock);

	printk(KERN_INFO "vCrypto: \n");
	return 0;
}

static ssize_t vcrypto_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos)
{
	struct miscdevice *misc = file->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	size_t bytes_to_read = min(count, (size_t)1024);

	mutex_lock(&chip->lock);

	if (copy_to_user(buf, chip->hw_buffer, bytes_to_read)) {
		mutex_unlock(&chip->lock);
		return -EFAULT;
	}

	mutex_unlock(&chip->lock);

	return bytes_to_read;
}

static ssize_t vcrypto_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct miscdevice *misc = file->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	size_t bytes_to_write = min(count, (size_t)1024);
	int i;

	mutex_lock(&chip->lock);

	if (copy_from_user(chip->hw_buffer, buf, bytes_to_write)) {
		mutex_unlock(&chip->lock);
		return -EFAULT;
	}

	for (i = 0; i < bytes_to_write; i++) {
		chip->hw_buffer[i] ^= (char)chip->current_key;
	}

	mutex_unlock(&chip->lock);

	return bytes_to_write;
}

static long vcrypto_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct miscdevice *misc = filep->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);
	int user_key;

	if (_IOC_TYPE(cmd) != VCRYPTO_MAGIC)
		return -ENOTTY;

	mutex_lock(&chip->lock);

	switch (cmd) {
		case VCRYPTO_SET_KEY:
			if (copy_from_user(&user_key, (int __user *)arg, sizeof(int))) {
				mutex_unlock(&chip->lock);
				return -EFAULT;
			}
			chip->current_key = user_key;
			printk(KERN_INFO "vCrypto: PID %d set new encryption key.\n", current->pid);
			break;

		case VCRYPTO_RESET:
			memset(chip->hw_buffer, 0, 1024);
			printk(KERN_INFO "vCrypto: PID %d triggered hardware reset.\n", current->pid);
			break;

		case VCRYPTO_GET_STATUS:
			if (copy_to_user((int __user *)arg, &chip->current_key, sizeof(int))) {
				mutex_unlock(&chip->lock);
				return -EFAULT;
			}

			printk(KERN_INFO "vCrypto: PID %d read hardware status.\n", current->pid);
			break;

		default:
			mutex_unlock(&chip->lock);
			return -ENOTTY;
	}

	return 0;
}

static const struct file_operations f_ops = {
	.owner		= THIS_MODULE,
	.open		= vcrypto_open,
	.release	= vcrypto_release,
	.read		= vcrypto_read,
	.write		= vcrypto_write,
	.unlocked_ioctl = vcrypto_ioctl,
};

static int __init vcrypto_init(void)
{
	int ret;

	vcrypto_chip = kmalloc(sizeof(struct vcrypto_data), GFP_KERNEL);
	if (!vcrypto_chip)
		return -ENOMEM;

	memset(vcrypto_chip, 0, sizeof(struct vcrypto_data));
	mutex_init(&vcrypto_chip->lock);

	vcrypto_chip->misc_dev.minor = MISC_DYNAMIC_MINOR;
	vcrypto_chip->misc_dev.name = "vcrypto";
	vcrypto_chip->misc_dev.fops = &f_ops;
	vcrypto_chip->misc_dev.mode = 0666;

	ret = misc_register(&vcrypto_chip->misc_dev);

	if (ret) {
		kfree(vcrypto_chip);
		return ret;
	}

	printk(KERN_INFO "vCrypto: \n");
	return 0;
}

static void __exit vcrypto_exit(void)
{
	misc_deregister(&vcrypto_chip->misc_dev);

	mutex_destroy(&vcrypto_chip->lock);
	kfree(vcrypto_chip);

	printk(KERN_INFO "vCrypto: Chip was removed!\n");
}

module_init(vcrypto_init);
module_exit(vcrypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcos Andrade <marcosandrade95963@gmail.com>.");
MODULE_DESCRIPTION("vCrypto - Virtual Cryptographic Coprocessor Driver.");
MODULE_VERSION("0.0.1");
