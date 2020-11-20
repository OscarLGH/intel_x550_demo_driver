#include "x550_mdev.h"

static int x550_mdev_create_vconfig_space(struct ixgbe_mdev_state *mdev_state)
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
	mdev_state->vconfig[0x88] = 0x00;
	
	mdev_state->vconfig[0x70] = 0x09;
	mdev_state->vconfig[0x71] = 0x60;
	mdev_state->vconfig[0x72] = 0x14;
	mdev_state->vconfig[0x73] = VIRTIO_PCI_CAP_NOTIFY_CFG;
	mdev_state->vconfig[0x74] = 0x04;
	
	mdev_state->vconfig[0x60] = 0x09;
	mdev_state->vconfig[0x61] = 0x50;
	mdev_state->vconfig[0x62] = 0x10;
	mdev_state->vconfig[0x63] = VIRTIO_PCI_CAP_DEVICE_CFG;
	mdev_state->vconfig[0x64] = 0x04;
	
	mdev_state->vconfig[0x50] = 0x09;
	mdev_state->vconfig[0x51] = 0x40;
	mdev_state->vconfig[0x52] = 0x10;
	mdev_state->vconfig[0x53] = VIRTIO_PCI_CAP_ISR_CFG;
	mdev_state->vconfig[0x54] = 0x04;
	
	mdev_state->vconfig[0x40] = 0x09;
	mdev_state->vconfig[0x41] = 0x00;
	mdev_state->vconfig[0x42] = 0x10;
	mdev_state->vconfig[0x43] = VIRTIO_PCI_CAP_COMMON_CFG;
	mdev_state->vconfig[0x44] = 0x04;

	/* intr PIN */
	mdev_state->vconfig[0x3d] = 0x1;
	
	mdev_state->bar0_virtio_config.host_access.common.device_status = 0;
	mdev_state->bar0_virtio_config.host_access.common.device_features = 
		VIRTIO_BLK_F_RO |
		VIRTIO_BLK_F_SIZE_MAX |
		VIRTIO_BLK_F_BLK_SIZE |
		VIRTIO_BLK_F_TOPOLOGY;
	mdev_state->bar0_virtio_config.host_access.common.queue_size = 0x100;
	mdev_state->bar0_virtio_config.host_access.common.queue_address = 0;

	mdev_state->bar0_virtio_config.host_access.blk.capacity = 0x1000;
	mdev_state->bar0_virtio_config.host_access.blk.size_max = 512;
	mdev_state->bar0_virtio_config.host_access.blk.seg_max = 1;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.cylinders = 255;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.heads = 1;
	mdev_state->bar0_virtio_config.host_access.blk.geometry.sectors = 4;
	mdev_state->bar0_virtio_config.host_access.blk.blk_size = 512;
	mdev_state->bar0_virtio_config.host_access.blk.alignment_offset = 512;
	mdev_state->bar0_virtio_config.host_access.blk.min_io_size = 512;
	mdev_state->bar0_virtio_config.host_access.blk.opt_io_size = 512;
	

	return 0;
}

static int x550_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct ixgbe_mdev_state *mdev_state = kzalloc(sizeof(*mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -EINVAL;
	mdev_state->mdev = mdev;
	x550_mdev_create_vconfig_space(mdev_state);
	mdev_set_drvdata(mdev, mdev_state);
	
	printk("x550-mdev vconfig space created.\n");
	return 0;
}

static int x550_mdev_remove(struct mdev_device *mdev)
{
	return 0;
}

static int x550_group_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ixgbe_mdev_state *mdev_state = container_of(nb, struct ixgbe_mdev_state, group_notifier);
	if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
		mdev_state->kvm = data;
	}

	return NOTIFY_OK;
}

static int x550_mdev_open(struct mdev_device *mdev)
{
	unsigned long events;
	int ret = 0;
	struct ixgbe_mdev_state *mdev_state = mdev_get_drvdata(mdev);

	mdev_state->group_notifier.notifier_call = x550_group_notifier;

	events = VFIO_GROUP_NOTIFY_SET_KVM;
	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events, &mdev_state->group_notifier);
	return 0;
}

static void x550_mdev_config_access(struct ixgbe_mdev_state *mdev_state, u32 offset, u32 size, bool rw, u32 *value)
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

struct virtio_blk_req {
	u32 type;
	u32 reserved;
	u64 sector;
	u8 status;
};

void *get_guest_access_ptr(struct kvm *kvm, u64 gpa)
{
	u64 gfn = gpa >> 12;
	u64 offset = gpa & 0xfff;
	void *ptr = page_to_virt(pfn_to_page(gfn_to_pfn(kvm, gfn))) + offset;
	printk("gpa = %llx, ptr = %llx\n", gpa, ptr);
	return ptr;
}

int x550_mdev_trigger_interrupt(struct ixgbe_mdev_state *mdev_state);

static int _vring_init(struct ixgbe_mdev_state *mdev_state)
{
	int queue_size = mdev_state->bar0_virtio_config.host_access.common.queue_size;
	unsigned long guest_pfn = mdev_state->bar0_virtio_config.host_access.common.queue_address;
	mdev_state->vring.desc = get_guest_access_ptr(mdev_state->kvm, guest_pfn << 12);
	mdev_state->vring.avail = (void *)((unsigned long)mdev_state->vring.desc + 16 * queue_size);
	mdev_state->vring.used = (void *)(round_up((unsigned long)mdev_state->vring.avail + 6 + 2 * queue_size, PAGE_SIZE));
	mdev_state->vring_avail_last_idx = 0;
	pr_info("desc = %llx, avail = %llx used = %llx\n", mdev_state->vring.desc, mdev_state->vring.avail, mdev_state->vring.used);
}

static int vring_process(struct ixgbe_mdev_state *mdev_state)
{
	int i;

	pr_info("mdev_state->vring.avail->idx = %d\n", mdev_state->vring.avail->idx);
	for (i = mdev_state->vring_avail_last_idx; i < mdev_state->vring.avail->idx; i++) {
		struct vring_desc *desc_ptr = &mdev_state->vring.desc[mdev_state->vring.avail->ring[i]];
		pr_info("avail ring idx = %d, ring = %d", i, mdev_state->vring.avail->ring[i]);
		while (1) {
			pr_info("vring desc: addr = 0x%llx len = %d, flags = %x, next = %x\n", desc_ptr->addr, desc_ptr->len, desc_ptr->flags, desc_ptr->next);
			if (desc_ptr->addr != 0) {
				struct virtio_blk_req *blk_req = get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr);
				if (desc_ptr->flags == 1) {
					pr_info("blk request:type = %x sector = %llx status = %x\n", blk_req->type, blk_req->sector, blk_req->status);
				} else if (desc_ptr->flags == 3) {
					memset(get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr), 0, desc_ptr->len);
				} else {
					*(u8 *)get_guest_access_ptr(mdev_state->kvm, desc_ptr->addr) = VIRTIO_BLK_S_OK;
				}
			}
			if ((desc_ptr->flags & VRING_DESC_F_NEXT) == 0)
				break;

			desc_ptr = &mdev_state->vring.desc[desc_ptr->next];
		}
		mdev_state->vring_avail_last_idx = mdev_state->vring.avail->idx;
		mdev_state->vring.used->ring[mdev_state->vring.used->idx].id = 0;
		mdev_state->vring.used->ring[mdev_state->vring.used->idx].len = 512;
		mdev_state->vring.used->idx = mdev_state->vring.avail->idx;
		x550_mdev_trigger_interrupt(mdev_state);
		x550_mdev_trigger_interrupt(mdev_state);
	}
}

static void x550_mdev_bar_access(struct ixgbe_mdev_state *mdev_state, u32 offset, u32 size, bool rw, u32 *value)
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
				printk("guest notify!");
				unsigned long guest_pfn = mdev_state->bar0_virtio_config.host_access.common.queue_address;
				struct vring_desc *desc_base;
				printk("guest pfn = %llx\n", guest_pfn);
				desc_base = get_guest_access_ptr(mdev_state->kvm, guest_pfn << 12);
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

static ssize_t x550_mdev_read(struct mdev_device *mdev, char __user *buf,
		size_t count, loff_t *pos)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	u32 index = (*pos) >> 40; //VFIO_PCI_OFFSET_TO_INDEX(*pos);
	u32 val = 0;
	u32 offset = (*pos) & 0xffffffff;
	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (count <= 4) {
			x550_mdev_config_access(mdev_state_p, offset, count, 0, &val);
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
		x550_mdev_bar_access(mdev_state_p, offset, count, 0, &val);
		printk("[MDEV RD][bar %d] %d bytes from offset %x, val = %x\n", index, count, offset, val);
		copy_to_user(buf, &val, count);
		break;
	default:
		return -EINVAL;
	
	}
	return count;
}

static ssize_t x550_mdev_write(struct mdev_device *mdev, const char __user *buf,
                size_t count, loff_t *pos)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	u32 index = (*pos) >> 40; //VFIO_PCI_OFFSET_TO_INDEX(*pos);
	u32 val = 0;
	u32 offset = (*pos) & 0xffffffff;
	copy_from_user(&val, buf, count);

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		x550_mdev_config_access(mdev_state_p, offset, count, 1, &val);
		printk("[MDEV WR][config] %d bytes value %x to offset %llx\n", count, val, offset);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		x550_mdev_bar_access(mdev_state_p, offset, count, 1, &val);
		printk("[MDEV WR][bar %d] %d bytes value %x to offset %llx\n", index, count, val, offset);
		break;
	default:
		return -EINVAL;
	
	}
	return count;
}

int x550_mdev_get_device_info(struct mdev_device *mdev, struct vfio_device_info *dev_info)
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

int x550_mdev_get_region_info(struct mdev_device *mdev, struct vfio_region_info *region_info)
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

	return 0;
}

int x550_mdev_get_irq_info(struct mdev_device *mdev, struct vfio_irq_info *irq_info)
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

static int x550_mdev_set_irqs(struct mdev_device *mdev, uint32_t flags,
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

	//mutex_lock(&mdev_state->ops_lock);
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

	//mutex_unlock(&mdev_state->ops_lock);
	return ret;
}

int x550_mdev_trigger_interrupt(struct ixgbe_mdev_state *mdev_state)
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
	pr_info("Intx triggered\n");
#if defined(DEBUG_INTR)
	pr_info("Intx triggered\n");
#endif
	if (ret != 1)
		pr_err("%s: eventfd signal failed (%d)\n", __func__, ret);

	return ret;
}

static long x550_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd, unsigned long arg)
{
	struct ixgbe_mdev_state *mdev_state_p = mdev_get_drvdata(mdev);
	int ret = 0;

	switch (cmd) {
		case VFIO_DEVICE_GET_INFO:
		{
			struct vfio_device_info info;
			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
				
			x550_mdev_get_device_info(mdev, &info);

			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EINVAL;
			break;
		}
		case VFIO_DEVICE_GET_REGION_INFO:
		{
			struct vfio_region_info info;

			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
			
			x550_mdev_get_region_info(mdev, &info);
			if (copy_to_user((void __user *)arg, &info, sizeof(info)))
				return -EINVAL;
			break;
		}
		case VFIO_DEVICE_GET_IRQ_INFO:
		{
			struct vfio_irq_info info;

			if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
				return -EINVAL;
			
			x550_mdev_get_irq_info(mdev, &info);
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

			ret = x550_mdev_set_irqs(mdev, hdr.flags, hdr.index, hdr.start,
				hdr.count, data);

			kfree(ptr);
			break;
		}
		case VFIO_DEVICE_RESET:
			printk("mdev reset.");
			x550_mdev_create_vconfig_space(mdev_state_p);
			break;
		default:
			break;
	}

	return ret;
}

static int x550_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	/*
	size_t size = vma->vm_end - vma->vm_start;
	int index;
	struct x550 *dev = PDE_DATA(file_inode(filp));
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

static void x550_mdev_release(struct mdev_device *mdev)
{

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
	return sprintf(buf, "x550-mdev-virtio\n");
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

static struct mdev_parent_ops x550_mdev_ops = {
	.owner = THIS_MODULE,
	.dev_attr_groups = virtio_blk_groups,
	.mdev_attr_groups = virtio_blk_mdev_groups,
	.supported_type_groups = mdev_typs_groups,
	.create = x550_mdev_create,
	.remove = x550_mdev_remove,
	.open = x550_mdev_open,
	.read = x550_mdev_read,
	.write = x550_mdev_write,
	.mmap = x550_mdev_mmap,
	.ioctl = x550_mdev_ioctl,
	.release = x550_mdev_release
};

int x550_mdev_init(struct device *dev)
{
	return mdev_register_device(dev, &x550_mdev_ops);
}

void x550_mdev_exit(struct device *dev)
{
	mdev_unregister_device(dev);
}
