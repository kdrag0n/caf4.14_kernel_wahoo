/*
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "ion.h"
#include "ion_system_secure_heap.h"

union ion_ioctl_arg {
	struct ion_allocation_data allocation;
	struct ion_heap_query query;
	struct ion_prefetch_data prefetch_data;
	struct ion_fd_data fd;
	struct ion_handle_data handle;
	struct ion_custom_data custom;
};

static int validate_ioctl_arg(unsigned int cmd, union ion_ioctl_arg *arg)
{
	int ret = 0;

	switch (cmd) {
	case ION_IOC_HEAP_QUERY:
		ret = arg->query.reserved0 != 0;
		ret |= arg->query.reserved1 != 0;
		ret |= arg->query.reserved2 != 0;
		break;
	default:
		break;
	}

	return ret ? -EINVAL : 0;
}

/* fix up the cases where the ioctl direction bits are incorrect */
static unsigned int ion_ioctl_dir(unsigned int cmd)
{
	switch (cmd) {
	case ION_IOC_SYNC:
	case ION_IOC_FREE:
	case ION_IOC_CUSTOM:
		return _IOC_WRITE;
	default:
		return _IOC_DIR(cmd);
	}
}

long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	unsigned int dir;
	union ion_ioctl_arg data;

	dir = ion_ioctl_dir(cmd);

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	/*
	 * The copy_from_user is unconditional here for both read and write
	 * to do the validate. If there is no write for the ioctl, the
	 * buffer is cleared
	 */
	if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	ret = validate_ioctl_arg(cmd, &data);
	if (ret) {
		pr_warn_once("%s: ioctl validate failed\n", __func__);
		return ret;
	}

	if (!(dir & _IOC_WRITE))
		memset(&data, 0, sizeof(data));

	switch (cmd) {
	case ION_IOC_ALLOC:
	{
		int fd;

		fd = ion_alloc_fd(data.allocation.len,
				  data.allocation.heap_mask,
				  data.allocation.flags);
		if (fd < 0)
			return fd;

		data.allocation.handle = fd;

		break;
	}
	case ION_IOC_FREE:
	{
		struct dma_buf *dmabuf = dma_buf_get(data.fd.fd);
		if (IS_ERR(dmabuf))
			return PTR_ERR(dmabuf);

		/*
		 * This is intentionally called twice:
		 *   - once to drop our temporary reference
		 *   - once to "free" by dropping another reference
		 */
		dma_buf_put(dmabuf);
		dma_buf_put(dmabuf);
		break;
	}
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	{
		/* Not dropping this reference is intentional */
		struct dma_buf *dmabuf = dma_buf_get(data.handle.handle);
		if (IS_ERR(dmabuf))
			return PTR_ERR(dmabuf);

		data.fd.fd = data.handle.handle;
		break;
	}
	case ION_IOC_IMPORT:
	{
		/* Not dropping this reference is intentional */
		struct dma_buf *dmabuf = dma_buf_get(data.fd.fd);
		if (IS_ERR(dmabuf))
			return PTR_ERR(dmabuf);

		data.handle.handle = data.fd.fd;
		break;
	}
	case ION_IOC_SYNC:
		ret = ion_sync_for_device(data.fd.fd);
		break;
	case ION_IOC_CUSTOM:
		pr_warn_ratelimited("ion: %s is using IOC_CUSTOM\n", current->comm);
		break;
	case ION_IOC_CLEAN_CACHES:
		pr_warn_ratelimited("ion: %s is using IOC_CLEAN_CACHES\n", current->comm);
		break;
	case ION_IOC_INV_CACHES:
		pr_warn_ratelimited("ion: %s is using IOC_INV_CACHES\n", current->comm);
		break;
	case ION_IOC_CLEAN_INV_CACHES:
		pr_warn_ratelimited("ion: %s is using IOC_CLEAN_INV_CACHES\n", current->comm);
		break;
	case ION_IOC_HEAP_QUERY:
		ret = ion_query_heaps(&data.query);
		break;
	case ION_IOC_PREFETCH:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_prefetch);
		if (ret)
			return ret;
		break;
	}
	case ION_IOC_DRAIN:
	{
		int ret;

		ret = ion_walk_heaps(data.prefetch_data.heap_id,
				     (enum ion_heap_type)
				     ION_HEAP_TYPE_SYSTEM_SECURE,
				     (void *)&data.prefetch_data,
				     ion_system_secure_heap_drain);

		if (ret)
			return ret;
		break;
	}
	default:
		return -ENOTTY;
	}

	if (dir & _IOC_READ) {
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd)))
			return -EFAULT;
	}
	return ret;
}
