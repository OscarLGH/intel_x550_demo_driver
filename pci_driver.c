#include "pci_driver.h"

struct class *ixgbe_class;
int instance = 0;

static struct pci_device_id
ixgbe_id_table[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_MODEL, PCI_DEVICE_ID_MODEL),
		.class = PCI_MODEL_BASE_CLASS << 16,
		.class_mask = 0xff << 16
	}	
};

static irqreturn_t ixgbe_irq(int irq, void *data)
{
	irqreturn_t result = IRQ_HANDLED;//IRQ_NONE
	struct ixgbe_hw *drv_data = data;

	schedule_work(&drv_data->irq_wq);
	return result;
}

static int ixgbe_char_open(struct inode *inode, struct file *file)
{
	struct ixgbe_hw *drv_data;
	drv_data = container_of(inode->i_cdev, struct ixgbe_hw, cdev);
	file->private_data = drv_data;

	return 0;
}

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
static loff_t ixgbe_char_lseek(struct file *file, loff_t offset, int origin)
{
	int index;
	loff_t retval = 0;
	struct ixgbe_hw *drv_data = file->private_data;

	switch (origin) {
		case SEEK_SET:
			file->f_pos = offset;
			break;
		case SEEK_END:
			file->f_pos = retval;
			break;
		default:
			break;
	}
	return retval;
}
static ssize_t ixgbe_char_read(struct file *file, char __user *buf,
		size_t count, loff_t *pos)
{
	int ret;
	int receive_len = 0;
	struct ixgbe_hw *hw = file->private_data;
	ret = packet_receive(hw, buf, &receive_len);
	if (receive_len < count)
		return 0;
	return count;
}

static ssize_t ixgbe_char_write(struct file *file, const char __user *buf,
                size_t count, loff_t *pos)
{
	int ret;
	struct ixgbe_hw *hw = file->private_data;
	ret = packet_transmit(hw, buf, count);
	*pos += count;
	return count;
}

static long ixgbe_char_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ixgbe_hw *drv_data = file->private_data;
	int ret = 0;

	switch (cmd) {
		case PCI_MODEL_IOCTL_SET_IRQFD:
			drv_data->efd_ctx = eventfd_ctx_fdget(arg);
			ret = 0;
			break;
		case PCI_MODEL_IOCTL_SET_IRQ:
			if (arg) {
			/* enable IRQ */

			} else {
			/* disable IRQ */

			}
			ret = 0;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

static int ixgbe_char_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t vma_size = vma->vm_end - vma->vm_start;
	int i, j;
	long current_offset = 0;
	long current_size = 0;
	struct ixgbe_hw *hw = file->private_data;

	switch (vma->vm_pgoff * PAGE_SIZE) {
		case 0:
		pgprot_noncached(vma->vm_page_prot);
		if (remap_pfn_range(vma,
				vma->vm_start,
				vma->vm_pgoff + pci_resource_start(hw->pdev, 0) / PAGE_SIZE,
				vma_size,
				vma->vm_page_prot)) {
			return -EAGAIN;
		}
		break;
		case 0x800000:
		for (i = 0; i < MAX_TX_RING; i++) {
			if (remap_pfn_range(vma,
					vma->vm_start + current_offset,
					page_to_pfn(hw->tx_desc_ring[i]->desc_ring_page),
					PAGE_SIZE,
					vma->vm_page_prot)) {
				return -EAGAIN;
			}
			current_offset += PAGE_SIZE;
		}
		break;
		case 0x880000:
		for (i = 0; i < MAX_RX_RING; i++) {
			if (remap_pfn_range(vma,
					vma->vm_start + current_offset,
					page_to_pfn(hw->rx_desc_ring[i]->desc_ring_page),
					PAGE_SIZE,
					vma->vm_page_prot)) {
				return -EAGAIN;
			}
			current_offset += PAGE_SIZE;
		}
		break;
		case 0x900000:
		for (i = 0; i < MAX_TX_RING; i++) {
			for (j = 0; j < RING_SIZE / 16; j++) {
				if (remap_pfn_range(vma,
						vma->vm_start + current_offset,
						page_to_pfn(hw->tx_desc_ring[i]->buffer_page_array[j]),
						PAGE_SIZE,
						vma->vm_page_prot)) {
					return -EAGAIN;
				}
				current_offset += PAGE_SIZE;
			}
		}
		break;
		case 0xa00000:
		for (i = 0; i < MAX_RX_RING; i++) {
			for (j = 0; j < RING_SIZE / 16; j++) {
				if (remap_pfn_range(vma,
						vma->vm_start + current_offset,
						page_to_pfn(hw->rx_desc_ring[i]->buffer_page_array[j]),
						PAGE_SIZE,
						vma->vm_page_prot)) {
					return -EAGAIN;
				}
				current_offset += PAGE_SIZE;
			}
		}
		break;
	}

	return 0;
}

static const struct file_operations ixgbe_char_fops = {
	.owner = THIS_MODULE,
	.open = ixgbe_char_open,
	.write = ixgbe_char_write,
	.read = ixgbe_char_read,
	.mmap = ixgbe_char_mmap,
	.unlocked_ioctl = ixgbe_char_ioctl,
	.llseek = ixgbe_char_lseek,
};

int ixgbe_device_fd_create(struct ixgbe_hw *pdm_dev)
{
	int ret;
	char buffer[256] = {0};
	struct pci_dev *pdev = pdm_dev->pdev;
	sprintf(buffer,
		"ixgbe_%02x:%02x.%02x",
		pdev->bus->number,
		(pdev->devfn >> 3) & 0x1f,
		pdev->devfn & 0x7,
		pdev->vendor,
		pdev->device
	);
	alloc_chrdev_region(&pdm_dev->dev, 0, 1, "ixgbe");

	cdev_init(&pdm_dev->cdev, &ixgbe_char_fops);
	cdev_add(&pdm_dev->cdev, pdm_dev->dev, 1);

	device_create(ixgbe_class, NULL, pdm_dev->dev, NULL, buffer);
	printk("add char file %d:%d for %s\n", pdm_dev->major, pdm_dev->minor, buffer);

	return 0;
}

int ixgbe_device_fd_destory(struct ixgbe_hw *pdm_dev)
{
	device_destroy(ixgbe_class, pdm_dev->dev);
	
	cdev_del(&pdm_dev->cdev);
	unregister_chrdev_region(pdm_dev->dev, 1);
	printk("intel x550 dev char file deleted.");
	return 0;
}

void irq_work_queue_func(struct work_struct *wq)
{
	struct ixgbe_hw *hw = container_of(wq, struct ixgbe_hw, irq_wq);
	u32 intr_cause;
	u32 link_status;
	int index;
	int i;
	char mac_string[18];

	intr_cause = IXGBE_READ_REG(hw, IXGBE_EICR);
	//printk("X550 INTR workqueue cause:%x\n", intr_cause);

	char *speed [] = {
				"reserved",
				"100 Mb/s",
				"1 GbE",
				"10 GbE",
				NULL
	};
	
	sprintf(mac_string,
		"%02x:%02x:%02x:%02x:%02x:%02x", 
		hw->mac_addr[0],
		hw->mac_addr[1],
		hw->mac_addr[2],
		hw->mac_addr[3],
		hw->mac_addr[4],
		hw->mac_addr[5]);

	if (intr_cause & IXGBE_EICR_LSC) {
		link_status = IXGBE_READ_REG(hw, IXGBE_LINKS);

		if (link_status & (1 << 30)) {
			printk("[%s] LINK UP. Speed:%s\n", mac_string, speed[((link_status >> 28) & 0x3)]);
		} else {
			printk("[%s] LINK DOWN\n", mac_string);
		}
	}

	if (intr_cause & 0xffff <= 0xffff) {
	
		if (hw->efd_ctx)
			eventfd_signal(hw->efd_ctx, intr_cause & 0xffff);

		hw->statistic.tx_packets += IXGBE_READ_REG(hw, IXGBE_TXDGPC);
		hw->statistic.tx_bytes += 
			(IXGBE_READ_REG(hw, IXGBE_TXDGBCL) + ((u64)IXGBE_READ_REG(hw, IXGBE_TXDGBCH) << 32));
		hw->statistic.rx_packets += IXGBE_READ_REG(hw, IXGBE_RXDGPC);
		hw->statistic.rx_bytes += 
			(IXGBE_READ_REG(hw, IXGBE_RXDGBCL) + ((u64)IXGBE_READ_REG(hw, IXGBE_RXDGBCH) << 32));
		hw->tx_desc_ring[0]->head = IXGBE_READ_REG(hw, IXGBE_TDH(0));
		hw->rx_desc_ring[0]->head = IXGBE_READ_REG(hw, IXGBE_RDH(0));
		hw->tx_desc_ring[0]->tail = IXGBE_READ_REG(hw, IXGBE_TDT(0));
		hw->rx_desc_ring[0]->tail = IXGBE_READ_REG(hw, IXGBE_RDT(0));
		printk("tx head = %d tail = %d\n", hw->tx_desc_ring[0]->head, hw->tx_desc_ring[0]->tail);
		printk("rx head = %d tail = %d\n", hw->rx_desc_ring[0]->head, hw->rx_desc_ring[0]->tail);
		if (hw->rx_desc_ring[0]->head == IXGBE_READ_REG(hw, IXGBE_RDT(0))) {
			//printk("rx ring empty.\n");
			hw->rx_desc_ring[0]->tail = (hw->rx_desc_ring[0]->head + hw->rx_desc_ring[0]->size / DESC_SIZE - 1) % (hw->rx_desc_ring[0]->size / DESC_SIZE);
			IXGBE_WRITE_REG(hw, IXGBE_RDT(0), hw->rx_desc_ring[0]->tail);
		}

		if ((hw->statistic.rx_packets != 0 && hw->statistic.rx_packets) ||
			(hw->statistic.tx_packets != 0 && hw->statistic.tx_packets % 100 == 0)
			) {
			printk("[%s] RX packets:%d (%d bytes) TX packets:%d (%d bytes)\n",
				mac_string,
				hw->statistic.rx_packets,
				hw->statistic.rx_bytes,
				hw->statistic.tx_packets,
				hw->statistic.tx_bytes
			);
		}
		if (hw->rx_desc_ring[0]->head != 0) {
			struct mac_frame_hdr *hdr = page_to_virt(hw->rx_desc_ring[0]->buffer_page_array[hw->rx_desc_ring[0]->head - 1]);
			printk("[%s] received packet from: %02x:%02x:%02x:%02x:%02x:%02x (dst:%02x:%02x:%02x:%02x:%02x:%02x)",
				mac_string,
				hdr->src_mac[0],
				hdr->src_mac[1],
				hdr->src_mac[2],
				hdr->src_mac[3],
				hdr->src_mac[4],
				hdr->src_mac[5],
				hdr->dst_mac[0],
				hdr->dst_mac[1],
				hdr->dst_mac[2],
				hdr->dst_mac[3],
				hdr->dst_mac[4],
				hdr->dst_mac[5]
				);
		}
		
	}
}


s32 ixgbe_get_mac_addr_generic(struct ixgbe_hw *hw, u8 *mac_addr)
{
	u32 rar_high;
	u32 rar_low;
	u16 i;

	rar_high = IXGBE_READ_REG(hw, IXGBE_RAH(0));
	rar_low = IXGBE_READ_REG(hw, IXGBE_RAL(0));

	for (i = 0; i < 4; i++)
		mac_addr[i] = (u8)(rar_low >> (i*8));

	for (i = 0; i < 2; i++)
		mac_addr[i+4] = (u8)(rar_high >> (i*8));

	return 0;
}

void ixgbe_reset(struct ixgbe_hw *hw)
{
	u32 ctrl, i;
	ctrl = IXGBE_CTRL_RST;
	ctrl |= IXGBE_READ_REG(hw, IXGBE_CTRL);
	IXGBE_WRITE_REG(hw, IXGBE_CTRL, ctrl);
	IXGBE_WRITE_FLUSH(hw);

	/* Poll for reset bit to self-clear indicating reset is complete */
	for (i = 0; i < 10; i++) {
		ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
		if (!(ctrl & IXGBE_CTRL_RST_MASK))
			break;
		udelay(1);
	}

	for (i = 0; i < 4; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_FCTTV(i), 0);
	}
	for (i = 0; i < 8; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_FCRTL(i), 0);
		IXGBE_WRITE_REG(hw, IXGBE_FCRTH(i), 0);
	}
	IXGBE_WRITE_REG(hw, IXGBE_FCRTV, 0);
	IXGBE_WRITE_REG(hw, IXGBE_FCCFG, 0);

	for (;;) {
		ctrl = IXGBE_READ_REG(hw, IXGBE_EEC_X550);
		if ((ctrl & IXGBE_EEC_ARD))
			break;
		udelay(1);
	}

	for (;;) {
		ctrl = IXGBE_READ_REG(hw, IXGBE_EEMNGCTL);
		if (1 || ((ctrl & (1 << 18) & (1 << 19)) == ((1 << 18)  | (1 << 19))))
			break;
		udelay(1);
	}

	for (;;) {
		ctrl = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
		if (ctrl & IXGBE_RDRXCTL_DMAIDONE)
			break;
		udelay(1);
	}

	IXGBE_WRITE_REG(hw, IXGBE_FCBUFF, 0);
	IXGBE_WRITE_REG(hw, IXGBE_FCFLT, 0);

	IXGBE_WRITE_REG(hw, IXGBE_IPSTXIDX, 0);
}

int tx_init(struct ixgbe_hw *hw)
{
	int i, j;
	u32 ctrl;
	void *buffer;
	dma_addr_t ring_dma_addr;
	dma_addr_t buffer_dma_addr;

	ctrl = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, ctrl);
	for (i = 0; i < MAX_TX_RING; i++) {
		hw->tx_desc_ring[i] = kmalloc(sizeof(*hw->tx_desc_ring[i]), GFP_KERNEL);
		hw->tx_desc_ring[i]->size = RING_SIZE;
		hw->tx_desc_ring[i]->buffer_page_array = kmalloc(hw->tx_desc_ring[i]->size / DESC_SIZE * sizeof(struct page *), GFP_KERNEL);
		hw->tx_desc_ring[i]->buffer_dma_addr_array = kmalloc(hw->tx_desc_ring[i]->size / DESC_SIZE * sizeof(dma_addr_t), GFP_KERNEL);
		hw->tx_desc_ring[i]->head = 0;
		hw->tx_desc_ring[i]->tail = 0;
		hw->tx_desc_ring[i]->tx_desc_ring = pci_alloc_consistent(hw->pdev, hw->tx_desc_ring[i]->size, &ring_dma_addr);
		hw->tx_desc_ring[i]->desc_ring_page = virt_to_page(hw->tx_desc_ring[i]->tx_desc_ring);
		//printk("tx ring addr:%llx\n", ring_dma_addr);
		memset(hw->tx_desc_ring[i]->tx_desc_ring, 0, hw->tx_desc_ring[i]->size);
		
		for (j = 0; j < hw->tx_desc_ring[i]->size / DESC_SIZE; j++) {
			buffer = pci_alloc_consistent(hw->pdev, PAGE_SIZE, &buffer_dma_addr);
			hw->tx_desc_ring[i]->buffer_page_array[j] = virt_to_page(buffer);
			hw->tx_desc_ring[i]->buffer_dma_addr_array[j] = buffer_dma_addr;
			hw->tx_desc_ring[i]->tx_desc_ring[j].read.buffer_addr = buffer_dma_addr;
			memset(buffer, 0, hw->rx_desc_ring[i]->size);
		}

		IXGBE_WRITE_REG(hw, IXGBE_TDBAL(i), ring_dma_addr);
		IXGBE_WRITE_REG(hw, IXGBE_TDBAH(i), ring_dma_addr >> 32);
		IXGBE_WRITE_REG(hw, IXGBE_TDLEN(i), hw->tx_desc_ring[i]->size);
		IXGBE_WRITE_REG(hw, IXGBE_TDH(i), hw->tx_desc_ring[i]->head);
		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(i), IXGBE_TXDCTL_ENABLE);
		IXGBE_WRITE_REG(hw, IXGBE_TDT(i), hw->tx_desc_ring[i]->tail);
	}

	ctrl = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
	IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL, ctrl | IXGBE_DMATXCTL_TE);
}

int rx_init(struct ixgbe_hw *hw)
{
	int i, j;
	u32 ctrl;
	void *buffer;
	dma_addr_t ring_dma_addr;
	dma_addr_t buffer_dma_addr;

	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, 0);
	//IXGBE_WRITE_REG(hw, IXGBE_FCTRL, IXGBE_FCTRL_SBP | IXGBE_FCTRL_MPE | IXGBE_FCTRL_UPE | IXGBE_FCTRL_BAM);

	ctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, ctrl ^ IXGBE_VLNCTRL_VFE);

	for (i = 0; i < MAX_RX_RING; i++) {
		//IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), 0);
		//IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(i), 0);
		//IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(i), 0);
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(i), 0x2 | (0x4 << 8) | (0x1 << 25));
		hw->rx_desc_ring[i] = kmalloc(sizeof(*hw->rx_desc_ring[i]), GFP_KERNEL);
		hw->rx_desc_ring[i]->size = RING_SIZE;
		hw->rx_desc_ring[i]->buffer_page_array = kmalloc(hw->rx_desc_ring[i]->size / DESC_SIZE * sizeof(struct page *), GFP_KERNEL);
		hw->rx_desc_ring[i]->buffer_dma_addr_array = kmalloc(hw->rx_desc_ring[i]->size / DESC_SIZE * sizeof(dma_addr_t), GFP_KERNEL);
		hw->rx_desc_ring[i]->rx_desc_ring = pci_alloc_consistent(hw->pdev, hw->rx_desc_ring[i]->size, &ring_dma_addr);
		hw->rx_desc_ring[i]->desc_ring_page = virt_to_page(hw->rx_desc_ring[i]->rx_desc_ring);
		hw->rx_desc_ring[i]->head = 0;
		hw->rx_desc_ring[i]->tail = hw->rx_desc_ring[i]->size / DESC_SIZE - 1;
		memset(hw->rx_desc_ring[i]->rx_desc_ring, 0, hw->rx_desc_ring[i]->size);

		//buffer = pci_alloc_consistent(hw->pdev, PAGE_SIZE, &buffer_dma_addr);
		for (j = 0; j < hw->rx_desc_ring[i]->size / DESC_SIZE; j++) {
			buffer = pci_alloc_consistent(hw->pdev, PAGE_SIZE, &buffer_dma_addr);
			hw->rx_desc_ring[i]->buffer_page_array[j] = virt_to_page(buffer);
			hw->rx_desc_ring[i]->buffer_dma_addr_array[j] = buffer_dma_addr;
			hw->rx_desc_ring[i]->rx_desc_ring[j].read.pkt_addr = buffer_dma_addr;
			hw->rx_desc_ring[i]->rx_desc_ring[j].read.hdr_addr = buffer_dma_addr + 0x800;
			memset(buffer, 0, hw->rx_desc_ring[i]->size);
		}

		IXGBE_WRITE_REG(hw, IXGBE_RDBAL(i), ring_dma_addr);
		IXGBE_WRITE_REG(hw, IXGBE_RDBAH(i), ring_dma_addr >> 32);
		IXGBE_WRITE_REG(hw, IXGBE_RDLEN(i), hw->rx_desc_ring[i]->size);
		IXGBE_WRITE_REG(hw, IXGBE_RDH(i), hw->rx_desc_ring[i]->head);
		IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(i), IXGBE_RXDCTL_ENABLE);
		IXGBE_WRITE_REG(hw, IXGBE_RDT(i), hw->rx_desc_ring[i]->tail);
	}
	IXGBE_WRITE_REG(hw, IXGBE_RXCTRL, IXGBE_RXCTRL_RXEN);
}

int packet_transmit(struct ixgbe_hw *hw, void __user *buffer, int len)
{
	int i;
	int free_queue = -1;
	union ixgbe_adv_tx_desc *tx_desc;
	free_queue = 0;
	void *tx_buffer_virt;
	int last_index;

	tx_buffer_virt = page_to_virt(hw->tx_desc_ring[free_queue]->buffer_page_array[hw->tx_desc_ring[free_queue]->tail]);
	tx_desc = hw->tx_desc_ring[free_queue]->tx_desc_ring;
	//memcpy(tx_buffer_virt, buffer, len);
	copy_from_user(tx_buffer_virt, buffer, len);
	tx_desc[hw->tx_desc_ring[free_queue]->tail].read.cmd_type_len = (0x2b << 24) | (0x3 << 20) | len;
	tx_desc[hw->tx_desc_ring[free_queue]->tail].read.olinfo_status = len << 14;
	last_index = hw->tx_desc_ring[free_queue]->tail;
	hw->tx_desc_ring[free_queue]->tail = (hw->tx_desc_ring[free_queue]->tail + 1) % (hw->tx_desc_ring[free_queue]->size / DESC_SIZE);
	IXGBE_WRITE_REG(hw, IXGBE_TDT(free_queue), hw->tx_desc_ring[free_queue]->tail);

	return 0;
}

int packet_receive(struct ixgbe_hw *hw, void __user *buffer, int *len)
{
	int i, j;
	int free_queue = -1;
	union ixgbe_adv_rx_desc *rx_desc;

	free_queue = 0;

	for (i = 0; i < MAX_RX_RING; i++) {
		for (j = 0; j < hw->rx_desc_ring[i]->size / DESC_SIZE; j++) {
			if (hw->rx_desc_ring[i]->rx_desc_ring[j].wb.upper.status_error & IXGBE_ADVTXD_STAT_DD) {
				*len = hw->rx_desc_ring[i]->rx_desc_ring[j].wb.upper.length;
				copy_to_user(buffer, page_to_virt(hw->rx_desc_ring[i]->buffer_page_array[j]), *len);
				hw->rx_desc_ring[i]->rx_desc_ring[j].read.pkt_addr = hw->rx_desc_ring[i]->buffer_dma_addr_array[j];
				hw->rx_desc_ring[i]->rx_desc_ring[j].read.hdr_addr = hw->rx_desc_ring[i]->buffer_dma_addr_array[j] + 0x800;
				goto done;
			}
		}
	}
	
error:
	return -EAGAIN;
done:
	return 0;
}
static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *pent)
{
	int ret;
	struct ixgbe_hw *drv_data = NULL;
	int i;
	u32 ivar = 0;

	drv_data = kmalloc(sizeof(*drv_data), GFP_KERNEL);
	if (drv_data == NULL) {
		return -ENOMEM;
	}
	memset(drv_data, 0, sizeof(*drv_data));

	pci_set_drvdata(pdev, drv_data);
	drv_data->pdev = pdev;

	ret = pci_enable_device(pdev);
	if (ret) {
		printk("enabling pci device failed.\n");
		return -ENODEV;
	}
	
	drv_data->mmio_virt = ioremap(
		pci_resource_start(pdev, 0),
		pci_resource_len(pdev, 0)
	);

	ixgbe_reset(drv_data);

	pci_set_master(pdev);

	drv_data->irq_count = 2;
	ret = pci_alloc_irq_vectors(pdev, 1, drv_data->irq_count, PCI_IRQ_MSIX);
	if (ret < 0) {
		printk("allocate IRQs failed.\n");
		return ret;
	}
	printk("allocated %d IRQ vectors.\n", ret);

	for (i = 0; i < drv_data->irq_count; i++) {
		ret = request_irq(pci_irq_vector(pdev, i), ixgbe_irq, 0,
			"intel x550", pci_get_drvdata(pdev));
	}

	INIT_WORK(&drv_data->irq_wq, irq_work_queue_func);

	ixgbe_device_fd_create(drv_data);
	
	ixgbe_get_mac_addr_generic(drv_data, drv_data->mac_addr);
	printk("MAC address:[%02x:%02x:%02x:%02x:%02x:%02x]", 
		drv_data->mac_addr[0],
		drv_data->mac_addr[1],
		drv_data->mac_addr[2],
		drv_data->mac_addr[3],
		drv_data->mac_addr[4],
		drv_data->mac_addr[5]);
	
	/* clear counters */
	IXGBE_READ_REG(drv_data, IXGBE_GPRC);
	IXGBE_READ_REG(drv_data, IXGBE_GPTC);

	rx_init(drv_data);
	tx_init(drv_data);

	//IXGBE_WRITE_REG(ixgbe, IXGBE_EICS, 0x7fffffff);
	IXGBE_WRITE_REG(drv_data, IXGBE_EIMS, 0x7fffffff);
	//IXGBE_WRITE_REG(ixgbe, IXGBE_EICS_EX(0), 0xffffffff);
	//IXGBE_WRITE_REG(ixgbe, IXGBE_EICS_EX(1), 0xffffffff);
	IXGBE_WRITE_REG(drv_data, IXGBE_EIMS_EX(0), 0xffffffff);
	IXGBE_WRITE_REG(drv_data, IXGBE_EIMS_EX(1), 0xffffffff);

	for (i = 0; i < 64; i++) {
		ivar = (i * 4) % 64;
		ivar = 0x80808080 | (ivar | ((ivar + 1) << 8) | ((ivar + 2) << 16) | ((ivar + 3) << 24));
		IXGBE_WRITE_REG(drv_data, IXGBE_IVAR(i), ivar);
	}

	IXGBE_WRITE_REG(drv_data, IXGBE_GPIE, IXGBE_GPIE_MSIX_MODE | IXGBE_GPIE_EIAME);

	instance++;

	return 0;
}

static void ixgbe_remove(struct pci_dev *pdev)
{
	int i;
	struct ixgbe_hw *drv_data = pci_get_drvdata(pdev);
	for (i = 0; i < 64; i++) {
		IXGBE_WRITE_REG(drv_data, IXGBE_IVAR(i), 0);
	}

	for (i = 0; i < drv_data->irq_count; i++) {
		irq_set_affinity_hint(pci_irq_vector(pdev, i), NULL);
		free_irq(pci_irq_vector(pdev, i), pci_get_drvdata(pdev));
	}
	pci_disable_msix(pdev);
	ixgbe_device_fd_destory(drv_data);
	
	kfree(drv_data);
}

static struct pci_driver
ixgbe_driver = {
	.name = "intel x550",
	.id_table = ixgbe_id_table,
	.probe = ixgbe_probe,
	.remove = ixgbe_remove
};

static int __init ixgbe_init(void)
{
	ixgbe_class = class_create(THIS_MODULE, "ixgbe");
	return pci_register_driver(&ixgbe_driver);
}

static void __exit ixgbe_exit(void)
{
	pci_unregister_driver(&ixgbe_driver);
	class_destroy(ixgbe_class);
}

module_init(ixgbe_init);
module_exit(ixgbe_exit);
MODULE_LICENSE("GPL");
