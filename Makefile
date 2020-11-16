obj-m +=ixgbe_driver.o
ixgbe_driver-y += x550_driver.o x550_mdev.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
