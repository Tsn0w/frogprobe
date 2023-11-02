obj-m += frogprobe_user.o

KBUILD_EXTRA_SYMBOLS := $(PWD)/../frogprobe_lkm/Module.symvers
EXTRA_CFLAGS =-I$(PWD)/../../../include --std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
