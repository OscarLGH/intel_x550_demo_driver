#include "pci_driver.h"

static int pci_driver_model_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	return 0;
}

static int pci_driver_model_mdev_remove(struct mdev_device *mdev)
{
	return 0;
}

static int pci_driver_model_mdev_open(struct mdev_device *mdev)
{
	// struct vdev = mdev_get_drvdata(mdev);
	return 0;
}


static ssize_t pci_driver_model_mdev_read(struct mdev_device *mdev, char __user *buf,
		size_t count, loff_t *pos)
{
	// struct vdev = mdev_get_drvdata(mdev);
	u32 index = (*pos) >> 40; //VFIO_PCI_OFFSET_TO_INDEX(*pos);
	u32 val = 0x12341234;
	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		copy_to_user(buf, &val, sizeof(val));
		break;
	default:
		return -EINVAL;
	
	}
	return 0;
}

static ssize_t pci_driver_model_mdev_write(struct mdev_device *mdev, const char __user *buf,
                size_t count, loff_t *pos)
{
	// struct vdev = mdev_get_drvdata(mdev);
	//u32 index = VFIO_PCI_OFFSET_TO_INDEX(*pos);
	return 0;
}

static long pci_driver_model_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd, unsigned long arg)
{
	// struct vdev = mdev_get_drvdata(mdev);
	int ret = 0;

	switch (cmd) {
		case 1:
			break;
		default:
			break;
	}

	return ret;
}

static int pci_driver_model_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	/*
	size_t size = vma->vm_end - vma->vm_start;
	int index;
	struct pci_driver_model *dev = PDE_DATA(file_inode(filp));
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

static void pci_driver_model_mdev_release(struct mdev_device *mdev)
{

}

static struct mdev_parent_ops pci_driver_model_vdev_ops = {
	//.mdev_attr_groups	= ...
	.create = pci_driver_model_mdev_create,
	.remove = pci_driver_model_mdev_remove,
	.open = pci_driver_model_mdev_open,
	.read = pci_driver_model_mdev_read,
	.write = pci_driver_model_mdev_write,
	.mmap = pci_driver_model_mdev_mmap,
	.ioctl = pci_driver_model_mdev_ioctl,
	.release = pci_driver_model_mdev_release
};

int pci_driver_model_mdev_init(struct device *dev, const void *ops)
{
	//return mdev_register_device(dev, &pci_driver_model_vdev_ops);
}
