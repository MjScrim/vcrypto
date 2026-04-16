obj-m += vcrypto.o

vcrypto-objs := vcrypto_main.o vcrypto_aes.o 
ccflags-y := -I$(src)/../../include

PWD := $(shell pwd)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
