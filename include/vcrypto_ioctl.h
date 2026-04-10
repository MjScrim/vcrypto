#ifndef VCRYPTO_IOCTL_H
#define VCRYPTO_IOCTL_H

#include <linux/ioctl.h>

#define VCRYPTO_MAGIC 'V'

#define VCRYPTO_SET_KEY _IOW(VCRYPTO_MAGIC, 0, int)
#define VCRYPTO_RESET _IO(VCRYPTO_IOCTL_H, 1)
#define VCRYPTO_GET_STATUS -IOR(VCRYPTO_MAGIC, 2, int)

#endif
