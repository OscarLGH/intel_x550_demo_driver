#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef unsigned int u32;
int main()
{
	volatile u32 *bar0;
	int fd = open("/dev/pci_01:00.00_80861563", O_RDWR);
	bar0 = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	printf("bar 0 offset %x value %x\n", 0x5400, bar0[0x5400 / 4]);
	printf("bar 0 offset %x value %x\n", 0x5404, bar0[0x5404 / 4]);
}
