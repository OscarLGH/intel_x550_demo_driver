#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/pci_ids.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>

#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>

#include <linux/vfio.h>
#include <linux/mdev.h>

#include <linux/eventfd.h>
#include <linux/workqueue.h>

#include <linux/delay.h>

#include "ixgbe_type.h"


#define PCI_VENDOR_ID_MODEL 0x8086
#define PCI_DEVICE_ID_MODEL 0x1563
#define PCI_MODEL_BASE_CLASS 0x2

struct pci_bar_reg {
	u64 phys;
	u32 *virt;
	long size;
};

struct pci_driver_model {
	struct pci_dev *pdev;
	spinlock_t lock;
	struct pci_bar_reg regs[6];
	void *oprom;
	u32 irq_cnt;
	u32 reserved;

	/* DMA buffer */
	dma_addr_t dma_buffer;
	void *dma_buffer_virt;
	size_t dma_buffer_size;

	int irq_count;

	/* for eventfd */
	struct eventfd_ctx *efd_ctx;

	/* work queue for irq buttom half */
	struct work_struct irq_wq;

	/* for char dev file */
	struct cdev cdev;
	dev_t dev;
};

/* basic ioctls */
#define PCI_MODEL_IOCTL_MAGIC 0x5536
#define PCI_MODEL_IOCTL_GET_BAR_INFO	_IOR(PCI_MODEL_IOCTL_MAGIC, 1, void *)
#define PCI_MODEL_IOCTL_SET_IRQFD	_IOW(PCI_MODEL_IOCTL_MAGIC, 2, void *)
#define PCI_MODEL_IOCTL_SET_IRQ	_IOW(PCI_MODEL_IOCTL_MAGIC, 3, void *)

/* vfio-mdev interfaces */
extern int pci_driver_model_mdev_init(struct device *dev, const void *ops);

struct ixgbe_tx_queue {
	union ixgbe_adv_tx_desc *tx_desc_ring;
	struct page *desc_ring_page;
	struct page **buffer_page_array;
	u64 size;
	u64 tail;
	u64 head;
};

struct ixgbe_rx_queue {
	union ixgbe_adv_rx_desc *rx_desc_ring;
	struct page *desc_ring_page;
	struct page **buffer_page_array;
	u64 size;
	u64 tail;
	u64 head;
};

struct ixgbe_statistic {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
};

struct ixgbe_hw {
	struct pci_dev *pdev;
	volatile u32 *mmio_virt;
	
	int irq_count;
	/* for eventfd */
	struct eventfd_ctx *efd_ctx;

	/* work queue for irq buttom half */
	struct work_struct irq_wq;

	/* for char dev file */
	struct cdev cdev;
	dev_t dev;
	int major, minor;
	
	struct ixgbe_tx_queue *tx_desc_ring[128];
	struct ixgbe_rx_queue *rx_desc_ring[128];
	struct ixgbe_statistic statistic;
	u8 mac_addr[6];
};

u32 ixgbe_read_reg(struct ixgbe_hw *hw, u32 reg);

u32 ixgbe_read_reg(struct ixgbe_hw *hw, u32 reg)
{
	return *(u32 *)(hw->mmio_virt + reg / 4);
}

#define IXGBE_READ_REG(a, reg) ixgbe_read_reg((a), (reg))

static inline void ixgbe_write_reg(struct ixgbe_hw *hw, u32 reg, u32 value)
{
	*(u32 *)(hw->mmio_virt + reg / 4) = value;
}
#define IXGBE_WRITE_REG(a, reg, value) ixgbe_write_reg((a), (reg), (value))

#define IXGBE_WRITE_FLUSH(a) ixgbe_read_reg((a), IXGBE_STATUS)


#define RING_SIZE 0x1000
#define MAX_TX_RING 1
#define MAX_RX_RING 1
#define DESC_SIZE sizeof(union ixgbe_adv_tx_desc)

struct mac_frame_hdr {
	u8 dst_mac[6];
	u8 src_mac[6];
	u16 type;
};

int packet_transmit(struct ixgbe_hw *hw, void __user *buffer, int len);
int packet_receive(struct ixgbe_hw *hw, void __user *buffer, int *len);
