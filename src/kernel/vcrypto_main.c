#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include "vcrypto_ioctl.h"
#include "vcrypto_aes.h"

#define BUFFER_SIZE 1024

struct vcrypto_data {
	char hw_buffer[BUFFER_SIZE];
	size_t current_len;
	uint8_t original_key[16];
	uint8_t expanded_key[176];
	struct mutex lock;
	struct miscdevice misc_dev;
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
		printk(KERN_WARNING "vCrypto: PID %d attempted to open, but device is busy.\n", current->pid);
		return -EBUSY;
	}

	chip->is_open = 1;
	mutex_unlock(&chip->lock);

	printk(KERN_INFO "vCrypto: Device opened successfully by PID %d.\n", current->pid);
	return 0;
}

static int vcrypto_release(struct inode *inodep, struct file *filep)
{
	struct miscdevice *misc = filep->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	mutex_lock(&chip->lock);
	chip->is_open = 0;
	mutex_unlock(&chip->lock);

	printk(KERN_INFO "vCrypto: Device closed and released by PID %d.\n", current->pid);
	return 0;
}

static ssize_t vcrypto_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos)
{
	struct miscdevice *misc = file->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	size_t bytes_to_read;

	mutex_lock(&chip->lock);

	bytes_to_read = min(count, chip->current_len);

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

	size_t max_input = BUFFER_SIZE - AES_BLOCK_SIZE;
	size_t bytes_to_write = min(count, max_input);
	size_t padded_len;
	int i;

	mutex_lock(&chip->lock);

	if (copy_from_user(chip->hw_buffer, buf, bytes_to_write)) {
		mutex_unlock(&chip->lock);
		return -EFAULT;
	}

	padded_len = aes_apply_padding((uint8_t *)chip->hw_buffer, chip->current_len, BUFFER_SIZE);

	if (padded_len == 0) {
		mutex_unlock(&chip->lock);
		return -ENOMEM;
	}

	chip->current_len = padded_len;

	for (i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
		aes_encrypt_block((uint8_t *)&chip->hw_buffer[i], chip->expanded_key);
	}

	mutex_unlock(&chip->lock);

	return bytes_to_write;
}

static long vcrypto_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct miscdevice *misc = filep->private_data;
	struct vcrypto_data *chip = container_of(misc, struct vcrypto_data, misc_dev);

	if (_IOC_TYPE(cmd) != VCRYPTO_MAGIC)
		return -ENOTTY;

	mutex_lock(&chip->lock);

	switch (cmd) {
		case VCRYPTO_SET_KEY:
			if (copy_from_user(chip->original_key, (uint8_t __user *)arg, AES_BLOCK_SIZE)) {
				mutex_unlock(&chip->lock);
				return -EFAULT;
			}
			aes_expand_key(chip->original_key, chip->expanded_key);
			printk(KERN_INFO "vCrypto: PID %d set new 128-bit AES key.\n", current->pid);
			break;

		case VCRYPTO_RESET:
			memset(chip->hw_buffer, 0, BUFFER_SIZE);
			chip->current_len = 0;
			memset(chip->expanded_key, 0, 176);
			memset(chip->original_key, 0, 16);
			printk(KERN_INFO "vCrypto: PID %d triggered hardware reset.\n", current->pid);
			break;

		case VCRYPTO_GET_STATUS:
			if (copy_to_user((uint8_t __user *)arg, chip->original_key, AES_BLOCK_SIZE)) {
				mutex_unlock(&chip->lock);
				return -EFAULT;
			}

			printk(KERN_INFO "vCrypto: PID %d read hardware status.\n", current->pid);
			break;

		default:
			mutex_unlock(&chip->lock);
			return -ENOTTY;
	}

	mutex_unlock(&chip->lock);

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

	printk(KERN_INFO "vCrypto: Virtual coprocessor initialized and registered successfully.\n");
	return 0;
}

static void __exit vcrypto_exit(void)
{
	misc_deregister(&vcrypto_chip->misc_dev);

	mutex_destroy(&vcrypto_chip->lock);
	kfree(vcrypto_chip);

	printk(KERN_INFO "vCrypto: Virtual coprocessor removed and memory freed.\n");
}

module_init(vcrypto_init);
module_exit(vcrypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcos Andrade <marcosandrade95963@gmail.com>.");
MODULE_DESCRIPTION("vCrypto - Virtual Cryptographic Coprocessor Driver.");
MODULE_VERSION("0.0.1");
