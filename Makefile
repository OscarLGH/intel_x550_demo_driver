obj-m +=ixgbe.o
ixgbe-y += ixgbe_driver.o ixgbe_mdev.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
