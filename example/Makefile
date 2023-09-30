obj-m += frog_probe.o

frog_probe-objs += frogprobe_main.o          \
				   ../src/encoder.o          \
				   ../src/frogprobe.o        \
				   ../src/symbol_extractor.o


EXTRA_CFLAGS =-I$(PWD)/../include --std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
