#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "../../include/vcrypto.h"
#include "../../include/vcrypto_ioctl.h"

#define DEVICE_PATH "/dev/vcrypto"

int vcrypto_connect(void)
{
	int fd = open(DEVICE_PATH, O_RDWR);

	return fd;
}

int vcrypto_set_key(int fd, const uint8_t *key)
{
	if (fd < 0 || !key)
		return -1;

	return ioctl(fd, VCRYPTO_SET_KEY, key);
}

int vcrypto_get_status(int fd, uint8_t *current_key)
{
	if (fd < 0 || !current_key)
		return -1;

	return ioctl(fd, VCRYPTO_GET_STATUS, current_key);
}

ssize_t vcrypto_process(int fd, const uint8_t *input, uint8_t *output, size_t len)
{
	ssize_t written_bytes, read_bytes;

	if (fd < 0 || !input || !output || len == 0)
		return -1;

	written_bytes = write(fd, input, len);
	if (written_bytes < 0)
		return -1;

	read_bytes = read(fd, output, written_bytes);

	return read_bytes;
}

int vcrypto_reset(int fd)
{
	if (fd < 0) return -1;
	return ioctl(fd, VCRYPTO_RESET);
}

void vcrypto_disconnect(int fd)
{
	if (fd >= 0) {
		close(fd);
	}
}
