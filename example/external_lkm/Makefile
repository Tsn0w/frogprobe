all:
	cd frogprobe_lkm && make
	cd user_lkm && make

clean:
	cd frogprobe_lkm && make clean
	cd user_lkm && make clean

install:
	insmod frogprobe_lkm/frogprobe.ko
	insmod user_lkm/frogprobe_user.ko

uninstall:
	rmmod user_lkm/frogprobe_user.ko
	rmmod frogprobe_lkm/frogprobe.ko
