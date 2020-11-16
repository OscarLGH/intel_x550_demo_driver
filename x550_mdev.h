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
#include <linux/vfio.h>
#include <linux/mdev.h>

struct mdev_region_info {
	u64 start;
	u64 phys_start;
	u64 size;
	u64 vfio_offset;
};
struct ixgbe_mdev_state {
	struct mdev_device *mdev;
	u8 vconfig[4096];
	struct mdev_region_info region_info[VFIO_PCI_NUM_REGIONS];
	int irq_fd;
	struct eventfd_ctx *msi_evtfd;
};

#define STORE_LE8(addr, val) (*(u8 *)addr = val)
#define STORE_LE16(addr, val) (*(u16 *)addr = val)
#define STORE_LE32(addr, val) (*(u32 *)addr = val)

#define LOAD_LE8(addr) (*(u8 *)addr)
#define LOAD_LE16(addr) (*(u16 *)addr)
#define LOAD_LE32(addr) (*(u32 *)addr)
