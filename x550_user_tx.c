#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct mac_frame_hdr {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
};

typedef unsigned int u32;
int main()
{
	int i, j;
	volatile u32 *bar0;
	int fd = open("/dev/ixgbe_01:00.01", O_RDWR);
	bar0 = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	printf("bar 0 offset %x value %x\n", 0x5400, bar0[0x5400 / 4]);
	printf("bar 0 offset %x value %x\n", 0x5404, bar0[0x5404 / 4]);
	
	unsigned char *test_buffer = malloc(0x1000);
	int len;
	memset(test_buffer, 0x0, 0x1000);
        unsigned char arp_packet[] = {
                 0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x50,0x56,0xc0,0x00,0x01,0x08,0x06,0x00,0x01,
                 0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x50,0x56,0xc0,0x00,0x01,0xc0,0xa8,0x00,0x01,
                 0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x00,0x02
        };
 
        struct mac_frame_hdr mac_frame = {
                {0xa0,0x36,0x9f,0xb9,0x89,0xbf},
                {0xaa,0x55,0x9f,0xb9,0x89,0xbe},
                0x0008
        };
        
        while (j < 1) {

		srand(time(NULL));
		i = rand();
		memcpy(arp_packet + 0, &i, 4);
		
		memcpy(test_buffer, &mac_frame, sizeof(mac_frame));
		memcpy(test_buffer + sizeof(mac_frame), arp_packet, sizeof(arp_packet));
		len = sizeof(mac_frame) + sizeof(arp_packet);
		printf("==============write===============\n");
		for (i = 0; i < len; i++) {
			printf("%02x ", test_buffer[i]);
		}
		printf("\n===================================\n");
		write(fd, test_buffer, len);
	
		j++;	
	}

}
