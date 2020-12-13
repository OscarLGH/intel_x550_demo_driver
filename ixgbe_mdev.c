#include "ixgbe_mdev.h"

static int ixgbe_mdev_create_vconfig_space(struct ixgbe_mdev_state *mdev_state)
{
	/* device ID */
	STORE_LE32(&mdev_state->vconfig[PCI_VENDOR_ID], 0x1af4);
	STORE_LE32(&mdev_state->vconfig[PCI_DEVICE_ID], 0x1001);
	STORE_LE32(&mdev_state->vconfig[PCI_SUBSYSTEM_VENDOR_ID], 0x1af4);
	STORE_LE32(&mdev_state->vconfig[PCI_SUBSYSTEM_ID], 0x0002);

	/* control */
	STORE_LE16(&mdev_state->vconfig[PCI_COMMAND], 0x0000);

	/* Rev ID */
	mdev_state->vconfig[PCI_REVISION_ID] = 0x00;

	/* interface */
	mdev_state->vconfig[PCI_CLASS_PROG] = 0x00;

	/* class */
	mdev_state->vconfig[PCI_CLASS_DEVICE] = 0x00;

	/* BARs */
	STORE_LE32(&mdev_state->vconfig[PCI_BASE_ADDRESS_0], 0x1);	/* BAR1: IO */

#define VIRTIO_CFG_BAR0 0
#define VIRTIO_CFG_BAR4 4
	/* Cap Ptr */
	mdev_state->vconfig[0x34] = 0x98;

	mdev_state->vconfig[0x98] = 0x11;
	mdev_state->vconfig[0x99] = 0x84;
	mdev_state->vconfig[0x9a] = 0x01;
	mdev_state->vconfig[0x9b] = 0x80;
	mdev_state->vconfig[0x9c] = 0x01;
	mdev_state->vconfig[0x9d] = 0x00;
	mdev_state->vconfig[0x9e] = 0x00;
	mdev_state->vconfig[0x9f] = 0x00;
	mdev_state->vconfig[0xa0] = 0x01;
	mdev_state->vconfig[0xa1] = 0x08;
	
	mdev_state->vconfig[0x84] = 0x09;
	mdev_state->vconfig[0x85] = 0x70;
	mdev_state->vconfig[0x86] = 0x14;
	mdev_state->vconfig[0x87] = VIRTIO_PCI_CAP_PCI_CFG;
	mdev_state->vconfig[0x88] = VIRTIO_CFG_BAR0;
	mdev_state->vconfig[0x89] = 0x00;
	mdev_state->vconfig[0x8a] = 0x00;
	mdev_state->vconfig[0x8b] = 0x00;
	
	mdev_state->vconfig[0x70] = 0x09;
	mdev_state->vconfig[0x71] = 0x60;
	mdev_state->vconfig[0x72] = 0x14;
	mdev_state->vconfig[0x73] = VIRTIO_PCI_CAP_NOTIFY_CFG;
	mdev_state->vconfig[0x74] = VIRTIO_CFG_BAR4;
	mdev_state->vconfig[0x75] = 0x00;
	mdev_state->vconfig[0x76] = 0x00;
	mdev_state->vconfig[0x77] = 0x00;
	mdev_state->vconfig[0x78] = 0x00;
	mdev_state->vconfig[0x79] = 0x30;
	mdev_state->vconfig[0x7a] = 0x00;
	mdev_state->vconfig[0x7b] = 0x00;
	mdev_state->vconfig[0x7c] = 0x00;
	mdev_state->vconfig[0x7d] = 0x10;
	mdev_state->vconfig[0x7e] = 0x00;
	mdev_state->vconfig[0x7f] = 0x00;
	
	mdev_state->vconfig[0x60] = 0x09;
	mdev_state->vconfig[0x61] = 0x50;
	mdev_state->vconfig[0x62] = 0x10;
	mdev_state->vconfig[0x63] = VIRTIO_PCI_CAP_DEVICE_CFG;
	mdev_state->vconfig[0x64] = VIRTIO_CFG_BAR4;
	mdev_state->vconfig[0x65] = 0x00;
	mdev_state->vconfig[0x66] = 0x00;
	mdev_state->vconfig[0x67] = 0x00;
	mdev_state->vconfig[0x68] = 0x00;
	mdev_state->vconfig[0x69] = 0x20;
	mdev_state->vconfig[0x6a] = 0x00;
	mdev_state->vconfig[0x6b] = 0x00;
	mdev_state->vconfig[0x6c] = 0x00;
	mdev_state->vconfig[0x6d] = 0x10;
	mdev_state->vconfig[0x6e] = 0x00;
	mdev_state->vconfig[0x6f] = 0x00;
	
	mdev_state->vconfig[0x50] = 0x09;
	mdev_state->vconfig[0x51] = 0x40;
	mdev_state->vconfig[0x52] = 0x10;
	mdev_state->vconfig[0x53] = VIRTIO_PCI_CAP_ISR_CFG;
	mdev_state->vconfig[0x54] = VIRTIO_CFG_BAR4;
	mdev_state->vconfig[0x55] = 0x00;
	mdev_state->vconfig[0x56] = 0x00;
	mdev_state->vconfig[0x57] = 0x00;
	mdev_state->vconfig[0x58] = 0x00;
	mdev_state->vconfig[0x59] = 0x10;
	mdev_state->vconfig[0x5a] = 0x00;
	mdev_state->vconfig[0x5b] = 0x00;
	mdev_state->vconfig[0x5c] = 0x00;
	mdev_state->vconfig[0x5d] = 0x10;
	mdev_state->vconfig[0x5e] = 0x00;
	mdev_state->vconfig[0x5f] = 0x00;
	
	mdev_state->vconfig[0x40] = 0x09;
	mdev_state->vconfig[0x41] = 0x00;
	mdev_state->vconfig[0x42] = 0x10;
	mdev_state->vconfig[0x43] = VIRTIO_PCI_CAP_COMMON_CFG;
	mdev_state->vconfig[0x44] = VIRTIO_CFG_BAR4;
	mdev_state->vconfig[0x45] = 0x00;
	mdev_state->vconfig[0x46] = 0x00;
	mdev_state->vconfig[0x47] = 0x00;

	/* intr line */
	mdev_state->vconfig[0x3c] = 0x30;

	/* intr PIN */
	mdev_state->vconfig[0x3d] = 0x1;
	
	mdev_state->bar0_virtio_config.host_access.common.device_status = 0;
	mdev_state->bar0_virtio_config.host_access.common.device_features = 
		VIRTIO_BLK_F_SIZE_MAX |
		VIRTIO_BLK_F_BLK_SIZE |
		VIRTIO_BLK_F_TOPOLOGY;
	mdev_state->bar0_virtio_config.host_access.common.queue_size = 0x100;
	mdev_state->bar0_virtio_config.host_access.common.queue_address = 0;

	mdev_state->bar0_virtio_config.host_access.blk.capacity = 0x2000000;
	mdev_state->bar0_virtio_config.host_access.blk.size_max = 512;
	mdev_state->bar0_virtio_config.host_access.blk.seg_max = 1;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.cylinders = 1;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.heads = 1;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.sectors = 0x2000000;
	mdev_state->bar0_virtio_config.host_access.blk.blk_size = 512;
	mdev_state->bar0_virtio_config.host_access.blk.alignment_offset = 512;
	mdev_state->bar0_virtio_config.host_access.blk.min_io_size = 512;
	mdev_state->bar0_virtio_config.host_access.blk.opt_io_size = 512;
	

	return 0;
}

static int ixgbe_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct ixgbe_mdev_state *mdev_state = kzalloc(sizeof(*mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -EINVAL;
	mdev_state->mdev = mdev;
	mdev_state->pdev_hw = dev_get_drvdata(mdev_parent_dev(mdev));
	mutex_init(&mdev_state->ops_lock);
	ixgbe_mdev_create_vconfig_space(mdev_state);
	mdev_set_drvdata(mdev, mdev_state);
	
	printk("ixgbe-mdev vconfig space created.\n");
	return 0;
}

static int ixgbe_mdev_remove(struct mdev_device *mdev)
{
	return 0;
}

static int ixgbe_group_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ixgbe_mdev_state *mdev_state = container_of(nb, struct ixgbe_mdev_state, group_notifier);
	if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
		mdev_state->kvm = data;
	}

	return NOTIFY_OK;
}

static int ixgbe_mdev_open(struct mdev_device *mdev)
{
	unsigned long events;
	int ret = 0;
	struct ixgbe_mdev_state *mdev_state = mdev_get_drvdata(mdev);

	mdev_state->group_notifier.notifier_call = ixgbe_group_notifier;

	events = VFIO_GROUP_NOTIFY_SET_KVM;
	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events, &mdev_state->group_notifier);
	return 0;
}

static void ixgbe_mdev_config_access(struct ixgbe_mdev_state *mdev_state, u32 offset, u32 size, bool rw, u32 *value)
{
	switch (size) {
	case 1:
		if (rw == 0) {
			*value = LOAD_LE8(&mdev_state->vconfig[offset]);
		} else {
			STORE_LE8(&mdev_state->vconfig[offset], *value);
		}
		break;
	case 2:
		if (rw == 0) {
			*value = LOAD_LE16(&mdev_state->vconfig[offset]);
		} else {
			STORE_LE16(&mdev_state->vconfig[offset], *value);
		}
		break;
	case 4:
		if (rw == 0) {
			*value = LOAD_LE32(&mdev_state->vconfig[offset]);
		} else {
			if (offset == 0x30) {
				*value = 0;
			} else if (offset >= 0x10 && offset << 0x24) {
				*value = (~(mdev_state->region_info[(offset - 0x10) / 4].size - 1) | mdev_state->vconfig[offset]);
				STORE_LE32(&mdev_state->vconfig[offset], *value);
			}
			STORE_LE32(&mdev_state->vconfig[offset], *value);
		}
		break;
	default:
		break;
	}
}

void *get_guest_access_ptr(struct kvm *kvm, u64 gpa)
{
	u64 gfn = gpa >> 12;
	u64 offset = gpa & 0xfff;
	void *ptr = page_to_virt(pfn_to_page(gfn_to_pfn(kvm, gfn))) + offset;
	//printk("gpa = %llx, ptr = %llx\n", gpa, ptr);
	return ptr;
}

int ixgbe_mdev_trigger_interrupt(struct ixgbe_mdev_state *mdev_state);

static int _vring_init(struct ixgbe_mdev_state *mdev_state)
{
	int queue_size = mdev_state->bar0_virtio_config.host_access.common.queue_size;
	unsigned long guest_pfn = mdev_state->bar0_virtio_config.host_access.common.queue_address;
	mdev_state->vring.desc = get_guest_access_ptr(mdev_state->kvm, guest_pfn << PAGE_SHIFT);
	//mdev_state->vring.avail = (void *)((unsigned long)mdev_state->vring.desc + 16 * queue_size);
	mdev_state->vring.avail = get_guest_access_ptr(mdev_state->kvm, (guest_pfn + 1) << PAGE_SHIFT);
	mdev_state->vring.used = get_guest_access_ptr(mdev_state->kvm, round_up(((guest_pfn + 1) << 12) + 6 + 2 * queue_size, PAGE_SIZE));
	mdev_state->vring_avail_last_idx = 0;
	pr_info("desc = %llx, avail = %llx used = %llx\n", mdev_state->vring.desc, mdev_state->vring.avail, mdev_state->vring.used);
}

#define PKT_VIRTIO_BLK_REQ 1
#define PKT_VIRTIO_BLK_DATA 2
#define PKT_VIRTIO_BLK_STATUS 3

int virtio_blk_send_req(struct ixgbe_mdev_state *mdev_state, struct virtio_blk_req *blk_req, long size)
{
	struct nic_payload_blk_req req = {
		.mac_hdr = {
			{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			{0x12, 0x34, 0x56, 0x78, 0xff, 0xff},
			0x0008
			},
		.pkt_ctrl = {
			.type = PKT_VIRTIO_BLK_REQ,
			.packet_seq = 0,
		},
	};

	memcpy(&req.mac_hdr.src_mac, mdev_state->pdev_hw->mac_addr, 6);
	memcpy(&req.blk_req, blk_req, sizeof(*blk_req));
	req.blk_req.size = size;
	packet_transmit_kern(mdev_state->pdev_hw, &req, sizeof(req));
}

u64 recv_seq = 0;
int virtio_blk_get_data(struct ixgbe_mdev_state *mdev_state, u64 gpa, long size)
{
	int recv_size = 0;
	char recv_buffer[1536];
	int pkt_size;
	int wait_flag = 0;
	int ret = -1;
	void *data;
	int checksum;
	int i;
	int remain_pkt = 0;
	int timeout = 0x200000;

	struct nic_payload_blk_data *pkt_data = (void *)recv_buffer;
	while (recv_size < size) {

		remain_pkt = mdev_state->pdev_hw->rx_desc_ring[0]->unhandled_pkt;
		if (remain_pkt == 0) {
			wait_for_pkt_recv(mdev_state->pdev_hw);
		}
		remain_pkt = mdev_state->pdev_hw->rx_desc_ring[0]->unhandled_pkt;
		spin_lock(&mdev_state->pdev_hw->rx_desc_ring[i]->lock);
		//printk("about to recievie %d pkts.\n",remain_pkt);
		if (mdev_state->pdev_hw->rx_desc_ring[0]->unhandled_pkt > 0) {
			mdev_state->pdev_hw->rx_desc_ring[0]->unhandled_pkt--;
		}
		spin_unlock(&mdev_state->pdev_hw->rx_desc_ring[i]->lock);

		ret = packet_receive_kern(mdev_state->pdev_hw, recv_buffer, &pkt_size);
		//printk("recv:pkt size = %d\n", pkt_size);
		//timeout--;
		//if (timeout == 0)
		//	return -1;
		if (ret == 0) {
			if (pkt_data->pkt_ctrl.type == PKT_VIRTIO_BLK_DATA) {
				recv_seq++;
				if (pkt_data->pkt_ctrl.packet_seq != recv_seq) {
					printk("packet seq not match! pkt_data->pkt_ctrl.packet_seq = %llx recv_seq = %llx\n");
				}
				
				//checksum = 0;
				//for (i = 0; i < pkt_data->pkt_ctrl.size / 4; i++) {
				//	checksum += ((u32 *)pkt_data->buffer)[i];
				//}
				recv_size += pkt_data->pkt_ctrl.size;
				//printk("pkt size = %d recv size = %d size = %d\n", pkt_data->pkt_ctrl.size, recv_size, size);
				if (((gpa + pkt_data->pkt_ctrl.size) >> PAGE_SHIFT) != (gpa >> PAGE_SHIFT) && ((gpa % pkt_data->pkt_ctrl.size) != 0)) {
					data = get_guest_access_ptr(mdev_state->kvm, gpa);
					memcpy(data, pkt_data->buffer, pkt_data->pkt_ctrl.size - (gpa % pkt_data->pkt_ctrl.size));
					data = get_guest_access_ptr(mdev_state->kvm, round_down(gpa + pkt_data->pkt_ctrl.size, PAGE_SIZE));
					memcpy(data, (u64)pkt_data->buffer + pkt_data->pkt_ctrl.size - (gpa % pkt_data->pkt_ctrl.size), gpa % pkt_data->pkt_ctrl.size);
				} else {
					data = get_guest_access_ptr(mdev_state->kvm, gpa);
					memcpy(data, pkt_data->buffer, pkt_data->pkt_ctrl.size);
				}
				
				//if (checksum != pkt_data->pkt_ctrl.checksum) {
				//	printk("checksum error.");
				//}
				//printk("receive data:%02x %02x size = %d\n", ((char *)data)[0], ((char *)data)[1], pkt_data->pkt_ctrl.size);
				if (pkt_data->pkt_ctrl.size != 512 && pkt_data->pkt_ctrl.size != 1024) {
					printk("pkt size mismatch.");
				}
				gpa += pkt_data->pkt_ctrl.size;
			} else {
				continue;
			}
		}
	}
}

u64 send_seq = 0;
int virtio_blk_send_data(struct ixgbe_mdev_state *mdev_state, u64 gpa, long size)
{
	int send_size = 0;
	char send_buffer[1536];
	int pkt_size;
	int ret = -1;
	void *data;
	int checksum;
	int i;

	struct nic_payload_blk_data pkt_data = {
		.mac_hdr = {
			{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			{0x12, 0x34, 0x56, 0x78, 0xff, 0xff},
			0x0008
			},
		.pkt_ctrl = {
			.type = PKT_VIRTIO_BLK_DATA,
			.packet_seq = 0,
		},
	};

	memcpy(&pkt_data.mac_hdr.src_mac, mdev_state->pdev_hw->mac_addr, 6);
	//ixgbe_disable_interrupt(mdev_state->pdev_hw);
	pkt_size = size > 512 ? 1024 : 512;
	while (send_size < size) {

		send_seq++;

		pkt_data.pkt_ctrl.packet_seq = send_seq;
		pkt_data.pkt_ctrl.size = pkt_size;

		if (((gpa + pkt_data.pkt_ctrl.size) >> PAGE_SHIFT) != (gpa >> PAGE_SHIFT) && ((gpa % pkt_data.pkt_ctrl.size) != 0)) {
			data = get_guest_access_ptr(mdev_state->kvm, gpa);
			memcpy(pkt_data.buffer, data, pkt_data.pkt_ctrl.size - (gpa % pkt_data.pkt_ctrl.size));
			data = get_guest_access_ptr(mdev_state->kvm, round_down(gpa + pkt_data.pkt_ctrl.size, PAGE_SIZE));
			memcpy((u64)pkt_data.buffer + pkt_data.pkt_ctrl.size - (gpa % pkt_data.pkt_ctrl.size), data, gpa % pkt_data.pkt_ctrl.size);
		} else {
			data = get_guest_access_ptr(mdev_state->kvm, gpa);
			memcpy(pkt_data.buffer, data, pkt_data.pkt_ctrl.size);
		}

		checksum = 0;
		//for (i = 0; i < pkt_data.pkt_ctrl.size / 4; i++) {
		//	checksum += ((u32 *)pkt_data.buffer)[i];
		//}
		pkt_data.pkt_ctrl.checksum = checksum;
		//printk("write:checksum = %x\n", checksum);		
		//if (checksum != pkt_data.pkt_ctrl.checksum) {
		//	printk("checksum error.");
		//}
		ret = packet_transmit_kern(mdev_state->pdev_hw, &pkt_data, sizeof(struct nic_payload_blk_data));

		send_size += pkt_data.pkt_ctrl.size;
		gpa += pkt_data.pkt_ctrl.size;
	}
	//ixgbe_reset_pmc(mdev_state->pdev_hw);
	//ixgbe_enable_interrupt(mdev_state->pdev_hw);
}

int virtio_blk_get_id(struct ixgbe_mdev_state *mdev_state, u64 gpa, long size)
{
	int recv_size = 0;
	char *device_id = "VIRTIO_OVER_IXGBE_V1";
	int pkt_size;
	int wait_flag = 0;
	int ret = -1;
	void *data;

	data = get_guest_access_ptr(mdev_state->kvm, gpa);
	memcpy(data, device_id, 20);
}

int virtio_blk_get_status(struct ixgbe_mdev_state *mdev_state)
{
	int recv_size = 0;
	char recv_buffer[1536];
	int pkt_size;
	struct nic_payload_blk_status *pkt_status = (void *)recv_buffer;
	packet_receive_kern(mdev_state->pdev_hw, recv_buffer, &pkt_size);
	if (pkt_status->pkt_ctrl.type == PKT_VIRTIO_BLK_STATUS) {
		return pkt_status->status;
	}
	
	return -1;
}

static int vring_process(struct ixgbe_mdev_state *mdev_state)
{
	int i;
	int len;
	int queue_size = mdev_state->bar0_virtio_config.host_access.common.queue_size;
	int seq = 0;
	int data_len;

	//pr_info("mdev_state->vring_avail_last_idx = %d mdev_state->vring.avail->idx = %d\n", mdev_state->vring_avail_last_idx, mdev_state->vring.avail->idx);
	for (i = mdev_state->vring_avail_last_idx % queue_size; i != mdev_state->vring.avail->idx % queue_size; i = (i + 1) % queue_size) {
		struct vring_desc *desc_ptr = &mdev_state->vring.desc[mdev_state->vring.avail->ring[i]];
		//pr_info("avail ring idx = %d, ring = %d", i, mdev_state->vring.avail->ring[i]);
		len = 0;
		seq = 0;
		
		while (1) {
			//pr_info("vring desc: addr = 0x%llx len = %d, flags = %x, next = %x\n", desc_ptr->addr, desc_ptr->len, desc_ptr->flags, desc_ptr->next);
			len += desc_ptr->len;
			if (desc_ptr->addr != 0) {
				struct virtio_blk_req *blk_req;
				if (seq == 0) {
					blk_req = get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr);
					//pr_info("blk request:type = %x ioprio = %x sector = %llx\n", blk_req->type, blk_req->ioprio, blk_req->sector);
					//virtio_blk_send_req(mdev_state, blk_req);
				} else if (seq == 1) {
					//memset(get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr), blk_req->sector, desc_ptr->len);
					if (blk_req->type == 0) {
						virtio_blk_send_req(mdev_state, blk_req, desc_ptr->len);
						//pr_info("sent blk request:type = %x ioprio = %x sector = %llx\n", blk_req->type, blk_req->ioprio, blk_req->sector);
						virtio_blk_get_data(mdev_state, desc_ptr->addr, desc_ptr->len);
						//printk("===receive done====\n");
					} else if (blk_req->type == 1){
						//virtio_blk_send_req(mdev_state, blk_req, desc_ptr->len);
						//virtio_blk_send_data(mdev_state, desc_ptr->addr, desc_ptr->len);
					} else if (blk_req->type == 8) {
						virtio_blk_get_id(mdev_state, desc_ptr->addr, desc_ptr->len);
					} else {
						printk("unknown request.type = %x\n", blk_req->type);
					}
				} else if (seq == 2) {
					*(u8 *)get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr) = 0;//virtio_blk_get_status(mdev_state);
				}
			}
			if ((desc_ptr->flags & VRING_DESC_F_NEXT) == 0)
				break;

			desc_ptr = &mdev_state->vring.desc[desc_ptr->next];
			seq++;
		}
		mdev_state->vring.used->ring[mdev_state->vring.used->idx % queue_size].id = mdev_state->vring.avail->ring[i];
		mdev_state->vring.used->ring[mdev_state->vring.used->idx % queue_size].len = len;
		mdev_state->vring.used->idx = ++mdev_state->vring_avail_last_idx;
		ixgbe_mdev_trigger_interrupt(mdev_state);
	}
}

static void ixgbe_mdev_bar_access(struct ixgbe_mdev_state *mdev_state, u32 offset, u32 size, bool rw, u32 *value)
{
	switch (size) {
	case 1:
		if (rw == 0) {
			*value = LOAD_LE8(&mdev_state->bar0_virtio_config.access_8[offset]);
			if (offset == 0x13) {
				STORE_LE8(&mdev_state->bar0_virtio_config.access_8[offset], 0);
			}
		} else {
			STORE_LE8(&mdev_state->bar0_virtio_config.access_8[offset], *value);
		}
		break;
	case 2:
		if (rw == 0) {
			*value = LOAD_LE16(&mdev_state->bar0_virtio_config.access_8[offset]);
		} else {
			if (offset == 0x10) {
				//printk("guest notify!");
				vring_process(mdev_state);
			} else {
				STORE_LE16(&mdev_state->bar0_virtio_config.access_8[offset], *value);
			}
		}
		break;
	case 4:
		if (rw == 0) {
			if (offset != 8) {
				*value = LOAD_LE32(&mdev_state->bar0_virtio_config.access_8[offset]);
			} else {
				*value = 0;
			}
			
		} else {
			STORE_LE32(&mdev_state->bar0_virtio_config.access_8[offset], *value);
			if (offset == 8) {
				_vring_init(mdev_state);
			}
		}
		break;
	default:
		break;
	}
}

static ssize_t ixgbe_mdev_read(struct mdev_device *mdev, char __user *buf,
		size_t count, loff_t *pos)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	u32 index = (*pos) >> 40; //VFIO_PCI_OFFSET_TO_INDEX(*pos);
	u32 val = 0;
	u32 offset = (*pos) & 0xffffffff;
	
	mutex_lock(&mdev_state_p->ops_lock);
	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (count <= 4) {
			ixgbe_mdev_config_access(mdev_state_p, offset, count, 0, &val);
			printk("[MDEV RD][config] %d bytes offset %x, val = %x\n", count, offset, val);
			copy_to_user(buf, &val, count);
		} else {
			copy_to_user(buf, &mdev_state_p->vconfig[offset], count);
		}
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		ixgbe_mdev_bar_access(mdev_state_p, offset, count, 0, &val);
		//printk("[MDEV RD][bar %d] %d bytes from offset %x, val = %x\n", index, count, offset, val);
		copy_to_user(buf, &val, count);
		break;
	default:
		break;
	
	}
	mutex_unlock(&mdev_state_p->ops_lock);
	return count;
}

static ssize_t ixgbe_mdev_write(struct mdev_device *mdev, const char __user *buf,
                size_t count, loff_t *pos)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	u32 index = (*pos) >> 40; //VFIO_PCI_OFFSET_TO_INDEX(*pos);
	u32 val = 0;
	u32 offset = (*pos) & 0xffffffff;
	
	mutex_lock(&mdev_state_p->ops_lock);
	copy_from_user(&val, buf, count);

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		printk("[MDEV WR][config] %d bytes value %x to offset %llx\n", count, val, offset);
		ixgbe_mdev_config_access(mdev_state_p, offset, count, 1, &val);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		//printk("[MDEV WR][bar %d] %d bytes value %x to offset %llx\n", index, count, val, offset);
		ixgbe_mdev_bar_access(mdev_state_p, offset, count, 1, &val);
		break;
	default:
		break;
	
	}
	mutex_unlock(&mdev_state_p->ops_lock);
	return count;
}

int ixgbe_mdev_get_device_info(struct mdev_device *mdev, struct vfio_device_info *dev_info)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);

	if (!mdev)
		return -EINVAL;

	if (!mdev_state_p)
		return -EINVAL;

	dev_info->flags = VFIO_DEVICE_FLAGS_PCI;
	dev_info->num_regions = VFIO_PCI_NUM_REGIONS;
	dev_info->num_irqs = VFIO_PCI_NUM_IRQS;

	return 0;
}

int ixgbe_mdev_get_region_info(struct mdev_device *mdev, struct vfio_region_info *region_info)
{
	u32 size = 0;
	u64 bar_index;
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);

	if (!mdev)
		return -EINVAL;

	if (!mdev_state_p)
		return -EINVAL;

	bar_index = region_info->index;
	printk("%s bar_index = %d\n", __FUNCTION__, bar_index);
	
	mutex_lock(&mdev_state_p->ops_lock);
	switch (bar_index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		size = 0x200;
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		size = 0x1000;
		break;
	case VFIO_PCI_BAR1_REGION_INDEX:
		size = 0x10000;
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
		size = 0x10000;
		break;
	default:
		size = 0;
	}

	mdev_state_p->region_info[bar_index].size = size;
	mdev_state_p->region_info[bar_index].vfio_offset = (bar_index << 40);

	region_info->size = size;
	region_info->offset = (bar_index << 40);
	region_info->flags = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
	
	mutex_unlock(&mdev_state_p->ops_lock);

	return 0;
}

int ixgbe_mdev_get_irq_info(struct mdev_device *mdev, struct vfio_irq_info *irq_info)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);

	if (!mdev)
		return -EINVAL;

	if (!mdev_state_p)
		return -EINVAL;

	irq_info->flags = VFIO_IRQ_INFO_EVENTFD;
	irq_info->count = 2;

	if (irq_info->index == VFIO_PCI_INTX_IRQ_INDEX)
		irq_info->flags |= (VFIO_IRQ_INFO_MASKABLE | VFIO_IRQ_INFO_AUTOMASKED);
	else
		irq_info->flags |= VFIO_IRQ_INFO_NORESIZE;

	return 0;
}

static int ixgbe_mdev_set_irqs(struct mdev_device *mdev, uint32_t flags,
			 unsigned int index, unsigned int start,
			 unsigned int count, void *data)
{
	int ret = 0;
	struct ixgbe_mdev_state *mdev_state;

	if (!mdev)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -EINVAL;

	mutex_lock(&mdev_state->ops_lock);
	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
		{
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				pr_info("%s: disable INTx\n", __func__);
				if (mdev_state->intx_evtfd)
					eventfd_ctx_put(mdev_state->intx_evtfd);
				break;
			}

			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;

				if (fd > 0) {
					struct eventfd_ctx *evt;

					evt = eventfd_ctx_fdget(fd);
					if (IS_ERR(evt)) {
						ret = PTR_ERR(evt);
						break;
					}
					mdev_state->intx_evtfd = evt;
					mdev_state->irq_fd = fd;
					mdev_state->irq_index = index;
					break;
				}
			}
			break;
		}
		}
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				if (mdev_state->msi_evtfd)
					eventfd_ctx_put(mdev_state->msi_evtfd);
				pr_info("%s: disable MSI\n", __func__);
				mdev_state->irq_index = VFIO_PCI_INTX_IRQ_INDEX;
				break;
			}
			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;
				struct eventfd_ctx *evt;

				if (fd <= 0)
					break;

				if (mdev_state->msi_evtfd)
					break;

				evt = eventfd_ctx_fdget(fd);
				if (IS_ERR(evt)) {
					ret = PTR_ERR(evt);
					break;
				}
				mdev_state->msi_evtfd = evt;
				mdev_state->irq_fd = fd;
				mdev_state->irq_index = index;
			}
			break;
	}
	break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		pr_info("%s: MSIX_IRQ\n", __func__);
		break;
	case VFIO_PCI_ERR_IRQ_INDEX:
		pr_info("%s: ERR_IRQ\n", __func__);
		break;
	case VFIO_PCI_REQ_IRQ_INDEX:
		pr_info("%s: REQ_IRQ\n", __func__);
		break;
	}

	mutex_unlock(&mdev_state->ops_lock);
	return ret;
}

int ixgbe_mdev_trigger_interrupt(struct ixgbe_mdev_state *mdev_state)
{
	int ret = -1;

	if ((mdev_state->irq_index == VFIO_PCI_MSI_IRQ_INDEX) &&
	    (!mdev_state->msi_evtfd))
		return -EINVAL;
	else if ((mdev_state->irq_index == VFIO_PCI_INTX_IRQ_INDEX) &&
		 (!mdev_state->intx_evtfd)) {
		pr_info("%s: Intr eventfd not found\n", __func__);
		return -EINVAL;
	}

	if (mdev_state->irq_index == VFIO_PCI_MSI_IRQ_INDEX)
		ret = eventfd_signal(mdev_state->msi_evtfd, 1);
	else
		ret = eventfd_signal(mdev_state->intx_evtfd, 1);
		
	mdev_state->bar0_virtio_config.host_access.common.isr_status = 0x1;
	//pr_info("INTR triggered, index = %d\n", mdev_state->irq_index);

	if (ret != 1)
		pr_err("%s: eventfd signal failed (%d)\n", __func__, ret);

	return ret;
}

static long ixgbe_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd, unsigned long arg)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	int ret = 0;

	switch (cmd) {
		case VFIO_DEVICE_GET_INFO:
		{
			struct vfio_device_info info;
			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
				
			ixgbe_mdev_get_device_info(mdev, &info);

			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EINVAL;
			break;
		}
		case VFIO_DEVICE_GET_REGION_INFO:
		{
			struct vfio_region_info info;

			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
			
			ixgbe_mdev_get_region_info(mdev, &info);
			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EINVAL;
			break;
		}
		case VFIO_DEVICE_GET_IRQ_INFO:
		{
			struct vfio_irq_info info;

			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
			
			ixgbe_mdev_get_irq_info(mdev, &info);
			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EINVAL;
			break;
		}
		case VFIO_DEVICE_SET_IRQS:
		{
			struct vfio_irq_set hdr;
			u8 *data = NULL, *ptr = NULL;
			size_t data_size = 0;
			int minsz;
			
			minsz = offsetofend(struct vfio_irq_set, count);
			if (copy_from_user(&hdr, (void __user *)arg, minsz))
				return -EFAULT;
				
			ret = vfio_set_irqs_validate_and_prepare(&hdr,
						VFIO_PCI_NUM_IRQS,
						VFIO_PCI_NUM_IRQS,
						&data_size);
			if (ret)
				return ret;
			
			if (data_size) {
			ptr = data = memdup_user((void __user *)(arg + minsz),
						 data_size);
			if (IS_ERR(data))
				return PTR_ERR(data);
			}

			ret = ixgbe_mdev_set_irqs(mdev, hdr.flags, hdr.index, hdr.start,
				hdr.count, data);

			kfree(ptr);
			break;
		}
		case VFIO_DEVICE_RESET:
			printk("mdev reset.");
			ixgbe_mdev_create_vconfig_space(mdev_state_p);
			break;
		default:
			break;
	}

	return ret;
}

static int ixgbe_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	/*
	size_t size = vma->vm_end - vma->vm_start;
	int index;
	struct ixgbe *dev = PDE_DATA(file_inode(filp));
	sscanf(filp->f_path.dentry->d_iname, "bar%d", &index);
	pgprot_noncached(vma->vm_page_prot);
	if (remap_pfn_range(vma,
			vma->vm_start,
			vma->vm_pgoff + dev->regs[index].phys / PAGE_SIZE,
			size,
			vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
	*/
	return 0;
}

static void ixgbe_mdev_release(struct mdev_device *mdev)
{
	unsigned long events;
	int ret = 0;
	struct ixgbe_mdev_state *mdev_state = mdev_get_drvdata(mdev);
	ret = vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &mdev_state->group_notifier);
	return ret;
}

static ssize_t virtio_blk_dev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "phy_device\n");
}
static DEVICE_ATTR_RO(virtio_blk_dev);

static struct attribute *virtio_blk_dev_attrs[] = {
	&dev_attr_virtio_blk_dev.attr,
	NULL,
};

struct attribute_group virtio_blk_group = {
	.name = "virtio-blk-virt",
	.attrs = virtio_blk_dev_attrs,
};

const struct attribute_group *virtio_blk_groups[] = {
	&virtio_blk_group,
	NULL,
};

static ssize_t virtio_blk_mdev_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "mdev_device\n");
}
static DEVICE_ATTR_RO(virtio_blk_mdev);

static struct attribute *virtio_blk_mdev_attrs[] = {
	&dev_attr_virtio_blk_mdev.attr,
	NULL,
};

struct attribute_group virtio_blk_mdev_group = {
	.name = "virtio-blk-virt-mdev",
	.attrs = virtio_blk_mdev_attrs,
};

const struct attribute_group *virtio_blk_mdev_groups[] = {
	&virtio_blk_mdev_group,
	NULL,
};

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "ixgbe-mdev-virtio\n");
}

MDEV_TYPE_ATTR_RO(name);

static ssize_t available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "instance 1\n");
}

MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "api\n");
}

MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group mdev_type_group1 = {
	.name = "1",
	.attrs = mdev_types_attrs,
};

struct attribute_group *mdev_typs_groups[] = {
	&mdev_type_group1,
	NULL,
};

static struct mdev_parent_ops ixgbe_mdev_ops = {
	.owner = THIS_MODULE,
	.dev_attr_groups = virtio_blk_groups,
	.mdev_attr_groups = virtio_blk_mdev_groups,
	.supported_type_groups = mdev_typs_groups,
	.create = ixgbe_mdev_create,
	.remove = ixgbe_mdev_remove,
	.open = ixgbe_mdev_open,
	.read = ixgbe_mdev_read,
	.write = ixgbe_mdev_write,
	.mmap = ixgbe_mdev_mmap,
	.ioctl = ixgbe_mdev_ioctl,
	.release = ixgbe_mdev_release
};

int ixgbe_mdev_init(struct device *dev)
{
	return mdev_register_device(dev, &ixgbe_mdev_ops);
}

void ixgbe_mdev_exit(struct device *dev)
{
	mdev_unregister_device(dev);
}
