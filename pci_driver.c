#include "pci_driver.h"

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

	printk("X550 IRQ:%d\n", irq);

	if (drv_data->efd_ctx)
		eventfd_signal(drv_data->efd_ctx, 1);

	schedule_work(&drv_data->irq_wq);
	return result;
}

static irqreturn_t ixgbe_irq_check(int irq, void *data)
{
	struct ixgbe_hw *drv_data = data;
	printk("IRQ:%d\n", irq);
	return IRQ_WAKE_THREAD;//IRQ_NONE
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
	struct ixgbe_hw *drv_data = file->private_data;
	return 0;
}

static ssize_t ixgbe_char_write(struct file *file, const char __user *buf,
                size_t count, loff_t *pos)
{
	struct ixgbe_hw *drv_data = file->private_data;
	return 0;
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
	int i = 0;
	long current_offset = 0;
	long current_size = 0;
	struct ixgbe_hw *drv_data = file->private_data;

	pgprot_noncached(vma->vm_page_prot);
	if (remap_pfn_range(vma,
			vma->vm_start,
			vma->vm_pgoff + pci_resource_start(drv_data->pdev, 0) / PAGE_SIZE,
			vma_size,
			vma->vm_page_prot)) {
		return -EAGAIN;
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
	int major, minor;
	int ret;
	char buffer[256] = {0};
	struct pci_dev *pdev = pdm_dev->pdev;
	sprintf(buffer,
		"pci_%02x:%02x.%02x_%04x%04x",
		pdev->bus->number,
		(pdev->devfn >> 3) & 0x1f,
		pdev->devfn & 0x7,
		pdev->vendor,
		pdev->device
	);
	alloc_chrdev_region(&pdm_dev->dev, 0, 255, "ixgbe_x550");
	major = MAJOR(pdm_dev->dev);
	minor = 0x20;

	cdev_init(&pdm_dev->cdev, &ixgbe_char_fops);
	pdm_dev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&pdm_dev->cdev, pdm_dev->dev, 1);

	pdm_dev->class = class_create(THIS_MODULE, "ixgbe_x550");
	device_create(pdm_dev->class, NULL, pdm_dev->dev, NULL, buffer);
	printk("add char file %d:%d for %s\n", major, minor, buffer);

	return 0;
}

int ixgbe_device_fd_destory(struct ixgbe_hw *pdm_dev)
{
	device_destroy(pdm_dev->class, pdm_dev->dev);
	class_destroy(pdm_dev->class);

	return 0;
}

void irq_work_queue_func(struct work_struct *wq)
{
	struct ixgbe_hw *drv_data = container_of(wq, struct ixgbe_hw, irq_wq);
	printk("work queue wakeup.\n");
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

#define RING_SIZE 0x1000
int tx_init(struct ixgbe_hw *hw)
{
	int i;
	u32 ctrl;

	ctrl = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, ctrl);
	for (i = 0; i < 128; i++) {
		hw->tx_desc_ring[i] = kmalloc(sizeof(*hw->tx_desc_ring[i]), GFP_KERNEL);
		hw->tx_desc_ring[i]->size = RING_SIZE;
		hw->tx_desc_ring[i]->head = 0;
		hw->tx_desc_ring[i]->tail = 0;
		hw->tx_desc_ring[i]->tx_desc_ring = kmalloc(hw->tx_desc_ring[i]->size, GFP_KERNEL);
		memset(hw->tx_desc_ring[i]->tx_desc_ring, 0, hw->tx_desc_ring[i]->size);
		//IXGBE_WRITE_REG(hw, IXGBE_TDBAL(i), VIRT2PHYS(hw->tx_desc_ring[i]->tx_desc_ring));
		//IXGBE_WRITE_REG(hw, IXGBE_TDBAH(i), VIRT2PHYS(hw->tx_desc_ring[i]->tx_desc_ring) >> 32);
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
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, 0);

	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, IXGBE_FCTRL_SBP | IXGBE_FCTRL_MPE | IXGBE_FCTRL_UPE | IXGBE_FCTRL_BAM);

	ctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, ctrl ^ IXGBE_VLNCTRL_VFE);

	for (i = 0; i < 1; i++) {
		//IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), 0);
		//IXGBE_WRITE_REG(hw, IXGBE_MPSAR_LO(i), 0);
		//IXGBE_WRITE_REG(hw, IXGBE_MPSAR_HI(i), 0);
		hw->rx_desc_ring[i] = kmalloc(sizeof(*hw->rx_desc_ring[i]), GFP_KERNEL);
		hw->rx_desc_ring[i]->size = RING_SIZE;
		hw->rx_desc_ring[i]->rx_desc_ring = kmalloc(hw->rx_desc_ring[i]->size, GFP_KERNEL);
		hw->rx_desc_ring[i]->head = 0;
		hw->rx_desc_ring[i]->tail = hw->rx_desc_ring[i]->size / sizeof(*hw->rx_desc_ring[i]->rx_desc_ring) - 1;
		memset(hw->rx_desc_ring[i]->rx_desc_ring, 0, hw->rx_desc_ring[i]->size);
		for (j = 0; j < hw->rx_desc_ring[i]->size / sizeof(*hw->rx_desc_ring[i]->rx_desc_ring); j++) {
			buffer = kmalloc(hw->rx_desc_ring[i]->size, GFP_KERNEL);
			//hw->rx_desc_ring[i]->rx_desc_ring[j].read.pkt_addr = VIRT2PHYS(buffer);
			memset(buffer, 0, hw->rx_desc_ring[i]->size);
		}
		//IXGBE_WRITE_REG(hw, IXGBE_RDBAL(i), VIRT2PHYS(hw->rx_desc_ring[i]->rx_desc_ring));
		//IXGBE_WRITE_REG(hw, IXGBE_RDBAH(i), VIRT2PHYS(hw->rx_desc_ring[i]->rx_desc_ring) >> 32);
		IXGBE_WRITE_REG(hw, IXGBE_RDLEN(i), hw->rx_desc_ring[i]->size);
		IXGBE_WRITE_REG(hw, IXGBE_RDH(i), hw->rx_desc_ring[i]->head);
		IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(i), IXGBE_RXDCTL_ENABLE);
		IXGBE_WRITE_REG(hw, IXGBE_RDT(i), hw->rx_desc_ring[i]->tail);
	}
	IXGBE_WRITE_REG(hw, IXGBE_RXCTRL, IXGBE_RXCTRL_RXEN);
}

void packet_transmit(struct ixgbe_hw *hw, void *buffer, int len)
{
	int i;
	int free_queue = -1;
	union ixgbe_adv_tx_desc *tx_desc;
/*
	while (1) {
		for (i = 0; i < 128; i++) {
			if (hw->tx_desc_ring[i]->tail == IXGBE_READ_REG(hw, IXGBE_TDH(i))) {
				free_queue = i;
				goto done;
			}
				
		}
	}
	*/
	free_queue = 0;
done:
	tx_desc = hw->tx_desc_ring[free_queue]->tx_desc_ring;
	//tx_desc[hw->tx_desc_ring[free_queue]->tail].read.buffer_addr = VIRT2PHYS(buffer);
	tx_desc[hw->tx_desc_ring[free_queue]->tail].read.cmd_type_len = (0xb << 24) | (36 << 16) | len;
	tx_desc[hw->tx_desc_ring[free_queue]->tail].read.olinfo_status = (0 << 16);
	hw->tx_desc_ring[free_queue]->tail = (hw->tx_desc_ring[free_queue]->tail + 1) % (hw->tx_desc_ring[free_queue]->size / sizeof(*tx_desc));

	IXGBE_WRITE_REG(hw, IXGBE_TDT(free_queue), hw->tx_desc_ring[free_queue]->tail);
}


static int ixgbe_probe(struct pci_dev *pdev, const struct pci_device_id *pent)
{
	int ret;
	struct ixgbe_hw *drv_data = NULL;
	int i;

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

	pci_set_master(pdev);
	
	drv_data->mmio_virt = ioremap(
		pci_resource_start(pdev, 0),
		pci_resource_len(pdev, 0)
	);

	drv_data->irq_count = 1;
	ret = pci_alloc_irq_vectors(pdev, 1, drv_data->irq_count, PCI_IRQ_MSIX);
	if (ret < 0) {
		printk("allocate IRQs failed.\n");
		return ret;
	}
	printk("allocated %d IRQ vectors.\n", ret);

	for (i = 0; i < drv_data->irq_count; i++) {
		ret = pci_request_irq(pdev, pci_irq_vector(pdev, i), ixgbe_irq_check, ixgbe_irq, pci_get_drvdata(pdev), "pci_driver_irq %d", pdev->irq);
	}

	INIT_WORK(&drv_data->irq_wq, irq_work_queue_func);

	ixgbe_device_fd_create(drv_data);
	
	ixgbe_reset(drv_data);
	
	ixgbe_get_mac_addr_generic(drv_data, drv_data->mac_addr);
	printk("MAC address:");
	for (i = 0; i < 5; i++) {
		printk("%02x:", drv_data->mac_addr[i]);
	}
	printk("%02x\n", drv_data->mac_addr[i]);

	return 0;
}

static void ixgbe_remove(struct pci_dev *pdev)
{
	struct ixgbe_hw *drv_data = pci_get_drvdata(pdev);
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
	return pci_register_driver(&ixgbe_driver);
}

static void __exit ixgbe_exit(void)
{
	pci_unregister_driver(&ixgbe_driver);
}

module_init(ixgbe_init);
module_exit(ixgbe_exit);
MODULE_LICENSE("GPL");
