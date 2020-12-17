#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <errno.h>

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
	u32 checksum;
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
	u64 padding;
};

struct nic_payload_blk_data {
	struct mac_frame_hdr mac_hdr;
	struct packet_ctrl pkt_ctrl;
	u8 buffer[1024];
	u64 padding;
};

struct nic_payload_blk_status {
	struct mac_frame_hdr mac_hdr;
	struct packet_ctrl pkt_ctrl;
	u32 status;
	u64 padding;
};

#define PCI_MODEL_IOCTL_MAGIC 0x5536
#define PCI_MODEL_IOCTL_GET_BAR_INFO	_IOR(PCI_MODEL_IOCTL_MAGIC, 1, void *)
#define PCI_MODEL_IOCTL_SET_IRQFD	_IOW(PCI_MODEL_IOCTL_MAGIC, 2, void *)
#define PCI_MODEL_IOCTL_SET_IRQ	_IOW(PCI_MODEL_IOCTL_MAGIC, 3, void *)

u64 seq = 0;

int recv_data(int fd, void *data, int len)
{
	int pkt_size = 1024;
	int len_0 = 0;
	int remain_size;
	int i;
	int checksum;
	unsigned char *recv_buffer = malloc(0x1000);
	u64 ret;
	struct nic_payload_blk_data *nic_payload_data = (void *)recv_buffer;
	struct nic_payload_blk_status *nic_payload_status = (void *)recv_buffer;

	pkt_size = 0;
	for (len_0 = 0; len_0 < len; len_0 += pkt_size) {

		checksum = 0;
		//for (i = 0; i < pkt_size / 4; i++) {
		//	checksum += ((u32*)data)[i];
		//}
		//nic_payload_data->mac_hdr.type = 0x0008;
		//nic_payload_data->pkt_ctrl.type = PKT_VIRTIO_BLK_DATA;
		//nic_payload_data->pkt_ctrl.size = pkt_size;
		//nic_payload_data->pkt_ctrl.checksum = checksum;
		//nic_payload_data->pkt_ctrl.packet_seq = ++seq;
		//printf("write size:%d\n", sizeof(*nic_payload_data));
		memset(nic_payload_data, 0, sizeof(*nic_payload_data));
		ret = read(fd, recv_buffer, sizeof(*nic_payload_data));
		if (ret == -1) {
			return -1;
		}
		//printf("%d bytes received.\n", nic_payload_data->pkt_ctrl.size, nic_payload_data->pkt_ctrl.checksum);
		if (nic_payload_data->pkt_ctrl.size != 0 && nic_payload_data->pkt_ctrl.type != PKT_VIRTIO_BLK_DATA) {
			printf("recv type error.%d \n", nic_payload_data->pkt_ctrl.type);
			continue;
		}
		if (nic_payload_data->pkt_ctrl.size == 0) {
			printf("unexcepted packet received.\n");
			break;
		}

		memcpy(data, nic_payload_data->buffer, nic_payload_data->pkt_ctrl.size);
		pkt_size = nic_payload_data->pkt_ctrl.size;
		data = (char *)data + pkt_size;
	}
	
	free(recv_buffer);
	//nic_payload_status->pkt_ctrl.type = PKT_VIRTIO_BLK_STATUS;
	//nic_payload_status->status = 0;
	//ret = write(fd, send_buffer, sizeof(*nic_payload_status));
	//if (ret == -1)
	//	return -1;
	return 0;
}

int read_file_send_data(int net_fd, int data_fd, u64 sector, u64 len)
{
	int send_size;
	int pkt_size;
	char *data_buffer = malloc(0x1000);
	int ret;
	send_size = 0;
	pkt_size = len > 512 ? 1024 : 512;
	struct nic_payload_blk_data *nic_payload_data = (void *)data_buffer;
	struct nic_payload_blk_status *nic_payload_status = (void *)data_buffer;

	while (send_size < len) {
		ret = lseek(data_fd, (sector + send_size / 512) * 512, SEEK_SET);
		if (ret == -1) {
			printf("lseek error.offset = %x ret = %d\n", (sector + send_size / 512) * 512, ret);
			return -1;
		}
		ret = read(data_fd, nic_payload_data->buffer, pkt_size);
		if (ret < 0) {
			printf("read file error.\n");
			return ret;
		}
		nic_payload_data->mac_hdr.type = 0x0008;
		nic_payload_data->pkt_ctrl.type = PKT_VIRTIO_BLK_DATA;
		nic_payload_data->pkt_ctrl.size = pkt_size;
		nic_payload_data->pkt_ctrl.checksum = 0;
		nic_payload_data->pkt_ctrl.packet_seq = ++seq;
		//printf("sending data offset %llx\n", send_size);
		ret = write(net_fd, data_buffer, sizeof(*nic_payload_data));
		if (ret == -1) {
			return -1;
		}
		send_size += pkt_size;
		//pkt_size = (len - send_size) > 1024 ? 512 : 512;
	}
	free(data_buffer);
	return 0;
}

int recv_data_write_file(int net_fd, int data_fd, u64 sector, u64 len)
{
	int recv_size;
	int pkt_size;
	char *data_buffer = malloc(0x1000);
	int ret;
	recv_size = 0;
	pkt_size = len > 512 ? 1024 : 512;
	struct nic_payload_blk_data *nic_payload_data = (void *)data_buffer;
	struct nic_payload_blk_status *nic_payload_status = (void *)data_buffer;

	while (recv_size < len) {
		ret = read(net_fd, data_buffer, sizeof(*nic_payload_data));
		if (ret == -1) {
			printf("recv error.offset = %x ret = %d\n", (sector + recv_size / 512) * 512, ret);
			return -1;
		}
		
		if (nic_payload_data->pkt_ctrl.size != 0 && nic_payload_data->pkt_ctrl.type != PKT_VIRTIO_BLK_DATA) {
			printf("recv type error.%d \n", nic_payload_data->pkt_ctrl.type);
			continue;
		}
		if (nic_payload_data->pkt_ctrl.size == 0) {
			printf("unexcepted packet received.\n");
			break;
		}

		ret = lseek(data_fd, (sector + recv_size / 512) * 512, SEEK_SET);
		if (ret == -1) {
			printf("lseek error.offset = %x ret = %d\n", (sector + recv_size / 512) * 512, ret);
			return -1;
		}
		
		//ret = write(data_fd, nic_payload_data->buffer, pkt_size);
		//if (ret < 0) {
		//	printf("write file error.\n");
		//	return ret;
		//}
		recv_size += pkt_size;
		pkt_size = (len - recv_size) > 512 ? 1024 : 512;
	}
	free(data_buffer);
	return 0;
}



int main(int argc, char **argv)
{
	int i;
	long ret;
	volatile u32 *bar0;
	int fd;
	int data_fd;
	int efd;
	long event = 0;

	if (argv[1] == NULL) {
		printf("no file specified.exiting");
		return -1;
	}

	fd = open("/dev/ixgbe_01:00.01", O_RDWR);
	if (fd < 0)
		return fd;
	data_fd = open(argv[1], O_RDWR);
	if (data_fd < 0)
		return data_fd;
	efd = eventfd(0, EFD_CLOEXEC);
	if (efd < 0)
		return efd;

	bar0 = mmap(NULL, 0x400000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	printf("bar 0 offset %x value %x\n", 0x5400, bar0[0x5400 / 4]);
	printf("bar 0 offset %x value %x\n", 0x5404, bar0[0x5404 / 4]);
	ioctl(fd, PCI_MODEL_IOCTL_SET_IRQFD, efd);
	unsigned char *recv_buffer = malloc(0x1000);
	unsigned char *data_buffer = malloc(0x1000);
	int len;
	int idx;
	int cnt = 0;
	struct virtio_blk_req req;

	struct nic_payload_blk_req *nic_payload_ptr;
	while (1) {
		//cnt = 0;
		ret = read(efd, &event, sizeof(long));
		//printf("event = %d\n", event);
		while (event--) {
			memset(recv_buffer, 0x0, 0x1000);
			memset(data_buffer, 0x0, 0x1000);
			read(fd, recv_buffer, 0x1000);
			nic_payload_ptr = (void *)recv_buffer;
			cnt++;
			
			if (nic_payload_ptr->pkt_ctrl.type == PKT_VIRTIO_BLK_REQ) {
				/*
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
				*/
				req.type = nic_payload_ptr->blk_req.type;
				req.sector = nic_payload_ptr->blk_req.sector;
				req.ioprio = nic_payload_ptr->blk_req.ioprio;
				req.size = nic_payload_ptr->blk_req.size;
				
				switch (nic_payload_ptr->blk_req.type) {
				case 0:
				{
					read_file_send_data(fd, data_fd, nic_payload_ptr->blk_req.sector, nic_payload_ptr->blk_req.size);
					break;
				}
				case 1:
				{
					recv_data_write_file(fd, data_fd, nic_payload_ptr->blk_req.sector, nic_payload_ptr->blk_req.size);
					break;
				}
				case 8:
				{
					break;
				}
				default:
				{
					printf("unknown request %x\n", nic_payload_ptr->blk_req.type);
					break;
				}
				}
			}
		}
	}
	

}
