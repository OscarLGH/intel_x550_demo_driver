#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

struct mac_frame_hdr {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
};

#define PKT_VIRTIO_BLK_REQ 1
#define PKT_VIRTIO_BLK_DATA 2
#define PKT_VIRTIO_BLK_STATUS 3

struct packet_ctrl {
	u32 type;
	u32 reserved;
	u64 packet_seq;
	u64 size;
};

struct virtio_blk_req {
	u32 type;
	u32 ioprio;
	u64 sector;
	u64 size; /* only for mdev-nic */
};

struct nic_payload_blk_req {
	struct mac_frame_hdr mac_hdr;
	struct packet_ctrl pkt_ctrl;
	struct virtio_blk_req blk_req;
};

struct nic_payload_blk_data {
	struct mac_frame_hdr mac_hdr;
	struct packet_ctrl pkt_ctrl;
	u8 buffer[1024];
};

struct nic_payload_blk_status {
	struct mac_frame_hdr mac_hdr;
	struct packet_ctrl pkt_ctrl;
	u32 status;
};

#define PCI_MODEL_IOCTL_MAGIC 0x5536
#define PCI_MODEL_IOCTL_GET_BAR_INFO	_IOR(PCI_MODEL_IOCTL_MAGIC, 1, void *)
#define PCI_MODEL_IOCTL_SET_IRQFD	_IOW(PCI_MODEL_IOCTL_MAGIC, 2, void *)
#define PCI_MODEL_IOCTL_SET_IRQ	_IOW(PCI_MODEL_IOCTL_MAGIC, 3, void *)

void send_data(int fd, void *data, int len)
{
	int pkt_size = 512;
	int len_0 = 0;
	unsigned char *send_buffer = malloc(0x1000);
	struct nic_payload_blk_data *nic_payload_data = (void *)send_buffer;
	struct nic_payload_blk_status *nic_payload_status = (void *)send_buffer;

	for (len_0 = 0; len_0 < len; len_0 += pkt_size) {
		memcpy(nic_payload_data->buffer, data, pkt_size);
		nic_payload_data->mac_hdr.type = 0x0008;
		nic_payload_data->pkt_ctrl.type = PKT_VIRTIO_BLK_DATA;
		nic_payload_data->pkt_ctrl.size = pkt_size;
		write(fd, send_buffer, sizeof(*nic_payload_data));
		data = (char *)data + pkt_size;
	}
	
	nic_payload_status->pkt_ctrl.type = PKT_VIRTIO_BLK_STATUS;
	nic_payload_status->status = 0;
	//write(fd, send_buffer, sizeof(*nic_payload_status));
}

typedef unsigned int u32;
int main()
{
	int i;
	int ret;
	volatile u32 *bar0;
	int fd = open("/dev/ixgbe_01:00.01", O_RDWR);
	int data_fd = open("vdisk.img", O_RDWR);
	int efd = eventfd(0, EFD_CLOEXEC);
	long event = 0;
	bar0 = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	printf("bar 0 offset %x value %x\n", 0x5400, bar0[0x5400 / 4]);
	printf("bar 0 offset %x value %x\n", 0x5404, bar0[0x5404 / 4]);
	ioctl(fd, PCI_MODEL_IOCTL_SET_IRQFD, efd);
	unsigned char *recv_buffer = malloc(0x1000);
	unsigned char *data_buffer = malloc(0x1000000);
	int len;
	int idx;
	int cnt = 0;
	struct nic_payload_blk_req *nic_payload_ptr;
	while (1) {
		//cnt = 0;
		memset(recv_buffer, 0x0, 0x1000);
		memset(data_buffer, 0x0, 0x1000000);
		ret = read(efd, &event, sizeof(long));
		//printf("event = %d\n", event);
		while (event--) {
			read(fd, recv_buffer, 32);
			nic_payload_ptr = (void *)recv_buffer;
			cnt++;
			printf("(%d) src:[%02x:%02x:%02x:%02x:%02x:%02x] blk request:type = %x sector = %x ioprio = %d size = %d\n",
				cnt,
				nic_payload_ptr->mac_hdr.src_mac[0],
				nic_payload_ptr->mac_hdr.src_mac[1],
				nic_payload_ptr->mac_hdr.src_mac[2],
				nic_payload_ptr->mac_hdr.src_mac[3],
				nic_payload_ptr->mac_hdr.src_mac[4],
				nic_payload_ptr->mac_hdr.src_mac[5],
				nic_payload_ptr->blk_req.type,
				nic_payload_ptr->blk_req.sector,
				nic_payload_ptr->blk_req.ioprio,
				nic_payload_ptr->blk_req.size
			);
			lseek(data_fd, nic_payload_ptr->blk_req.sector * 512, SEEK_SET);
			read(data_fd, data_buffer, nic_payload_ptr->blk_req.size);
			send_data(fd, data_buffer, nic_payload_ptr->blk_req.size);
		}
	}
	

}
