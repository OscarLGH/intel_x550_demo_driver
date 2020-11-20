#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/pci_ids.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <linux/vfio.h>
#include <linux/mdev.h>

#include <linux/eventfd.h>

#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_blk.h>

#include <linux/kvm_host.h>

struct mdev_region_info {
	u64 start;
	u64 phys_start;
	u64 size;
	u64 vfio_offset;
};

struct virtio_config {
	union {
		struct {
			struct {
				u32 device_features;
				u32 guest_features;
				u32 queue_address;
				u16 queue_size;
				u16 queue_select;
				u16 queue_notify;
				u8 device_status;
				u8 isr_status;
				//u16 config_msix_vector;
				//u16 queue_msix_vector;
			} common;
			struct virtio_blk_config blk;
		} host_access;
		u8 access_8[24 + sizeof(struct virtio_blk_config)];
		u16 access_16[12 + sizeof(struct virtio_blk_config) / 2];
		u32 access_32[6  + sizeof(struct virtio_blk_config) / 4];
	}
};

struct ixgbe_mdev_state {
	struct mdev_device *mdev;
	u8 vconfig[4096];
	struct mdev_region_info region_info[VFIO_PCI_NUM_REGIONS];
	
	struct virtio_pci_cap pci_cap[6];	
	struct virtio_pci_common_cfg pci_comm_cfg;

	struct virtio_config bar0_virtio_config;
	struct vring vring;
	int vring_avail_last_idx;

	int num_irqs;
	int irq_fd;
	int irq_index;
	struct eventfd_ctx *intx_evtfd;
	struct eventfd_ctx *msi_evtfd;

	struct notifier_block iommu_notifier;
	struct notifier_block group_notifier;

	struct kvm *kvm;
};

#define STORE_LE8(addr, val) (*(u8 *)addr = val)
#define STORE_LE16(addr, val) (*(u16 *)addr = val)
#define STORE_LE32(addr, val) (*(u32 *)addr = val)

#define LOAD_LE8(addr) (*(u8 *)addr)
#define LOAD_LE16(addr) (*(u16 *)addr)
#define LOAD_LE32(addr) (*(u32 *)addr)
