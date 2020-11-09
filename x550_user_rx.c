#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

struct mac_frame_hdr {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
};

#define PCI_MODEL_IOCTL_MAGIC 0x5536
#define PCI_MODEL_IOCTL_GET_BAR_INFO	_IOR(PCI_MODEL_IOCTL_MAGIC, 1, void *)
#define PCI_MODEL_IOCTL_SET_IRQFD	_IOW(PCI_MODEL_IOCTL_MAGIC, 2, void *)
#define PCI_MODEL_IOCTL_SET_IRQ	_IOW(PCI_MODEL_IOCTL_MAGIC, 3, void *)

typedef unsigned int u32;
int main()
{
	int i;
	int ret;
	volatile u32 *bar0;
	int fd = open("/dev/ixgbe_01:00.00", O_RDWR);
	int efd = eventfd(0, EFD_CLOEXEC);
	long event = 0;
	bar0 = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	printf("bar 0 offset %x value %x\n", 0x5400, bar0[0x5400 / 4]);
	printf("bar 0 offset %x value %x\n", 0x5404, bar0[0x5404 / 4]);
	ioctl(fd, PCI_MODEL_IOCTL_SET_IRQFD, efd);
	unsigned char *test_buffer = malloc(0x1000);
	int len;
	while (1) {
		memset(test_buffer, 0x0, 0x1000);
		ret = read(efd, &event, sizeof(long));
		printf("event = %d\n", event);
		ret = read(fd, test_buffer, 32);
		printf("===========read============\n");
		for (i = 0; i < 32; i++) {
			printf("%02x ", test_buffer[i]);
		}
		printf("\n=========================\n");
	}
	

}
