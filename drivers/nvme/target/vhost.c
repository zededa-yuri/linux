#include <linux/module.h>
#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include "../../vhost/vhost.h"
#include "nvmet.h"

#define NVMET_VHOST_AQ_DEPTH		256

enum NvmeCcShift {
	CC_MPS_SHIFT	= 7,
	CC_IOSQES_SHIFT	= 16,
	CC_IOCQES_SHIFT	= 20,
};

enum NvmeCcMask {
	CC_MPS_MASK	= 0xf,
	CC_IOSQES_MASK	= 0xf,
	CC_IOCQES_MASK	= 0xf,
};

#define NVME_CC_MPS(cc)    ((cc >> CC_MPS_SHIFT)    & CC_MPS_MASK)
#define NVME_CC_IOSQES(cc) ((cc >> CC_IOSQES_SHIFT) & CC_IOSQES_MASK)
#define NVME_CC_IOCQES(cc) ((cc >> CC_IOCQES_SHIFT) & CC_IOCQES_MASK)

enum NvmeAqaShift {
	AQA_ASQS_SHIFT	= 0,
	AQA_ACQS_SHIFT	= 16,
};

enum NvmeAqaMask {
	AQA_ASQS_MASK	= 0xfff,
	AQA_ACQS_MASK	= 0xfff,
};

#define NVME_AQA_ASQS(aqa) ((aqa >> AQA_ASQS_SHIFT) & AQA_ASQS_MASK)
#define NVME_AQA_ACQS(aqa) ((aqa >> AQA_ACQS_SHIFT) & AQA_ACQS_MASK)

#define NVME_CQ_FLAGS_PC(cq_flags)	(cq_flags & 0x1)
#define NVME_CQ_FLAGS_IEN(cq_flags)	((cq_flags >> 1) & 0x1)

#define NVME_SQ_FLAGS_PC(sq_flags)	(sq_flags & 0x1)

struct nvmet_vhost_ctrl_eventfd {
	struct file *call;
	struct eventfd_ctx *call_ctx;
	int __user *irq_enabled;
	int __user *vector;
};

struct nvmet_vhost_cq {
	struct nvmet_cq		cq;
	struct nvmet_vhost_ctrl	*ctrl;

	u32			head;
	u32			tail;
	u8			phase;
	u64			dma_addr;
	struct eventfd_ctx	*eventfd;
};

struct nvmet_vhost_sq {
	struct nvmet_sq		sq;
	struct nvmet_vhost_ctrl	*ctrl;

	u32			head;
	u32			tail;
	u64			dma_addr;
	u16			cqid;
};

struct nvmet_vhost_ctrl {
	struct vhost_dev dev;
	struct nvmet_vhost_ctrl_eventfd *eventfd;

	u16 cntlid;
	struct nvmet_ctrl *ctrl;
	u32 num_queues;

	struct nvmet_vhost_cq **cqs;
	struct nvmet_vhost_sq **sqs;
	struct nvmet_vhost_cq admin_cq;
	struct nvmet_vhost_sq admin_sq;

	u32 aqa;
	u64 asq;
	u64 acq;
	u16 cqe_size;
	u16 sqe_size;
	u16 max_prp_ents;
	u16 page_bits;
	u32 page_size;
};

const struct vhost_memory_region *
find_region(struct vhost_dev *hba, __u64 addr, __u32 len)
{
	struct vhost_memory *mem;
	struct vhost_memory_region *reg;
	int i;

	if (!hba->memory)
		return NULL;

	mem = hba->memory;
	/* linear search is not brilliant, but we really have on the order of 6
	 * regions in practice */
	for (i = 0; i < mem->nregions; ++i) {
		reg = mem->regions + i;
		if (reg->guest_phys_addr <= addr &&
		    reg->guest_phys_addr + reg->memory_size - 1 >= addr)
			return reg;
	}
	return NULL;
}

static bool check_region_boundary(const struct vhost_memory_region *reg,
				  uint64_t addr, size_t len)
{
	unsigned long max_size;

	max_size = reg->memory_size - addr + reg->guest_phys_addr;
	return (max_size < len);
}

static void __user *map_to_region(const struct vhost_memory_region *reg,
				   uint64_t addr)
{
	return (void __user *)(unsigned long)
		(reg->userspace_addr + addr - reg->guest_phys_addr);
}

static void __user *map_guest_to_host(struct vhost_dev *dev,
				       uint64_t addr, int size)
{
	const struct vhost_memory_region *reg = NULL;

	reg = find_region(dev, addr, size);
	if (unlikely(!reg))
		return ERR_PTR(-EPERM);

	if (unlikely(check_region_boundary(reg, addr, size)))
		return ERR_PTR(-EFAULT);

	return map_to_region(reg, addr);
}

static int nvmet_vhost_rw(struct vhost_dev *dev, u64 guest_pa,
		void *buf, uint32_t size, int write)
{
	void __user *host_user_va;
	void *host_kernel_va;
	struct page *page;
	uintptr_t offset;
	int ret;

	host_user_va = map_guest_to_host(dev, guest_pa, size);
	if (unlikely(!host_user_va)) {
		pr_warn("cannot map guest addr %p, error %ld\n",
			(void *)guest_pa, PTR_ERR(host_user_va));
		return -EINVAL;
	}

	ret = get_user_pages(current, dev->mm,
				(unsigned long)host_user_va, 1,
				false, 0, &page, NULL);
	if (unlikely(ret != 1)) {
		pr_warn("get_user_pages fail!!!\n");
		return -EINVAL;
	}

	host_kernel_va = kmap(page);
	if (unlikely(!host_kernel_va)) {
		pr_warn("kmap fail!!!\n");
		put_page(page);
		return -EINVAL;
	}

	offset = (uintptr_t)host_user_va & ~PAGE_MASK;
	if (write)
		memcpy(host_kernel_va + offset, buf, size);
	else
		memcpy(buf, host_kernel_va + offset, size);
	kunmap(host_kernel_va);
	put_page(page);

	return 0;
}

int nvmet_vhost_read(struct vhost_dev *dev, u64 guest_pa,
		void *buf, uint32_t size)
{
	return nvmet_vhost_rw(dev, guest_pa, buf, size, 0);
}

int nvmet_vhost_write(struct vhost_dev *dev, u64 guest_pa,
		void *buf, uint32_t size)
{
	return nvmet_vhost_rw(dev, guest_pa, buf, size, 1);
}

#define sq_to_vsq(sq) container_of(sq, struct nvmet_vhost_sq, sq)
#define cq_to_vcq(cq) container_of(cq, struct nvmet_vhost_cq, cq)

static int nvmet_vhost_check_sqid(struct nvmet_ctrl *n, u16 sqid)
{
	return sqid <= n->subsys->max_qid && n->sqs[sqid] != NULL ? 0 : -1;
}

static int nvmet_vhost_check_cqid(struct nvmet_ctrl *n, u16 cqid)
{
	return cqid <= n->subsys->max_qid && n->cqs[cqid] != NULL ? 0 : -1;
}

static int nvmet_vhost_init_cq(struct nvmet_vhost_cq *cq,
		struct nvmet_vhost_ctrl *n, u64 dma_addr,
		u16 cqid, u16 size, struct eventfd_ctx *eventfd,
		u16 vector, u16 irq_enabled)
{
	cq->ctrl = n;
	cq->dma_addr = dma_addr;
	cq->phase = 1;
	cq->head = cq->tail = 0;
	cq->eventfd = eventfd;
	n->cqs[cqid] = cq;

	nvmet_cq_init(n->ctrl, &cq->cq, cqid, size);

	return 0;
}

static int nvmet_vhost_init_sq(struct nvmet_vhost_sq *sq,
		struct nvmet_vhost_ctrl *n, u64 dma_addr,
		u16 sqid, u16 cqid, u16 size)
{
	sq->ctrl = n;
	sq->dma_addr = dma_addr;
	sq->cqid = cqid;
	sq->head = sq->tail = 0;
	n->sqs[sqid] = sq;

	nvmet_sq_init(n->ctrl, &sq->sq, sqid, size);

	return 0;
}

static void nvmet_vhost_start_ctrl(void *opaque)
{
	struct nvmet_vhost_ctrl *n = opaque;
	u32 page_bits = NVME_CC_MPS(n->ctrl->cc) + 12;
	u32 page_size = 1 << page_bits;
	int ret;

	n->page_bits = page_bits;
	n->page_size = page_size;
	n->max_prp_ents = n->page_size / sizeof(uint64_t);
	n->cqe_size = 1 << NVME_CC_IOCQES(n->ctrl->cc);
	n->sqe_size = 1 << NVME_CC_IOSQES(n->ctrl->cc);

	nvmet_vhost_init_cq(&n->admin_cq, n, n->acq, 0,
		NVME_AQA_ACQS(n->aqa) + 1, n->eventfd[0].call_ctx,
		0, 1);

	ret = nvmet_vhost_init_sq(&n->admin_sq, n, n->asq, 0, 0,
		NVME_AQA_ASQS(n->aqa) + 1);
	if (ret) {
		pr_warn("nvmet_vhost_init_sq failed!!!\n");
		BUG_ON(1);
	}
}

static void nvmet_vhost_create_cq(struct nvmet_req *req)
{
	struct nvmet_cq *cq;
	struct nvmet_vhost_cq *vcq;
	struct nvmet_vhost_ctrl *n;
	struct nvme_create_cq *c;
	u16 cqid;
	u16 vector;
	u16 qsize;
	u16 qflags;
	u64 prp1;
	int status;
	int ret;

	cq = req->cq;
	vcq = cq_to_vcq(cq);
	n = vcq->ctrl;
	c = &req->cmd->create_cq;
	cqid = le16_to_cpu(c->cqid);
	vector = le16_to_cpu(c->irq_vector);
	qsize = le16_to_cpu(c->qsize);
	qflags = le16_to_cpu(c->cq_flags);
	prp1 = le64_to_cpu(c->prp1);
	status = NVME_SC_SUCCESS;

	if (!cqid || (cqid && !nvmet_vhost_check_cqid(n->ctrl, cqid))) {
		status = NVME_SC_QID_INVALID | NVME_SC_DNR;
		goto out;
	}
	if (!qsize || qsize > NVME_CAP_MQES(n->ctrl->cap)) {
		status = NVME_SC_QUEUE_SIZE | NVME_SC_DNR;
		goto out;
	}
	if (!prp1) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto out;
	}
	if (vector > n->num_queues) {
		status = NVME_SC_INVALID_VECTOR | NVME_SC_DNR;
		goto out;
	}
	if (!(NVME_CQ_FLAGS_PC(qflags))) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto out;
	}

	vcq = kmalloc(sizeof(*vcq), GFP_KERNEL);
	if (!vcq) {
		status = NVME_SC_INTERNAL | NVME_SC_DNR;
		goto out;
	}

	ret = nvmet_vhost_init_cq(vcq, n, prp1, cqid, qsize+1,
		n->eventfd[cqid].call_ctx, vector,
		NVME_CQ_FLAGS_IEN(qflags));
	if (ret)
		status = NVME_SC_INTERNAL | NVME_SC_DNR;

out:
	nvmet_req_complete(req, status);
}

static void nvmet_vhost_create_sq(struct nvmet_req *req)
{
	struct nvme_create_sq *c = &req->cmd->create_sq;
	u16 cqid = le16_to_cpu(c->cqid);
	u16 sqid = le16_to_cpu(c->sqid);
	u16 qsize = le16_to_cpu(c->qsize);
	u16 qflags = le16_to_cpu(c->sq_flags);
	u64 prp1 = le64_to_cpu(c->prp1);

	struct nvmet_sq *sq = req->sq;
	struct nvmet_vhost_sq *vsq;
	struct nvmet_vhost_ctrl *n;
	int status;
	int ret;

	status = NVME_SC_SUCCESS;
	vsq = sq_to_vsq(sq);
	n = vsq->ctrl;

	if (!cqid || nvmet_vhost_check_cqid(n->ctrl, cqid)) {
		status = NVME_SC_CQ_INVALID | NVME_SC_DNR;
		goto out;
	}
	if (!sqid || (sqid && !nvmet_vhost_check_sqid(n->ctrl, sqid))) {
		status = NVME_SC_QID_INVALID | NVME_SC_DNR;
		goto out;
	}
	if (!qsize || qsize > NVME_CAP_MQES(n->ctrl->cap)) {
		status = NVME_SC_QUEUE_SIZE | NVME_SC_DNR;
		goto out;
	}
	if (!prp1 || prp1 & (n->page_size - 1)) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto out;
	}
	if (!(NVME_SQ_FLAGS_PC(qflags))) {
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto out;
	}

	vsq = kmalloc(sizeof(*vsq), GFP_KERNEL);
	if (!sq) {
		status = NVME_SC_INTERNAL | NVME_SC_DNR;
		goto out;
	}

	ret = nvmet_vhost_init_sq(vsq, n, prp1, sqid, cqid, qsize + 1);
	if (ret)
		status = NVME_SC_INTERNAL | NVME_SC_DNR;

out:
	nvmet_req_complete(req, status);
}

static int nvmet_vhost_parse_admin_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	switch (cmd->common.opcode) {
	case nvme_admin_create_cq:
		req->execute = nvmet_vhost_create_cq;
		req->data_len = 0;
		return 0;
	case nvme_admin_create_sq:
		req->execute = nvmet_vhost_create_sq;
		req->data_len = 0;
		return 0;
	}

	return -1;
}

static int
nvmet_vhost_set_endpoint(struct nvmet_vhost_ctrl *n,
			struct vhost_nvme_target *c)
{
	struct nvmet_subsys *subsys;
	struct nvmet_ctrl *ctrl;
	int num_queues;
	int ret = 0;

	subsys = nvmet_find_subsys(c->vhost_wwpn);
        if (!subsys) {
		pr_warn("connect request for invalid subsystem!\n");
		return -EINVAL;
	}

	mutex_lock(&subsys->lock);
	ctrl = nvmet_alloc_ctrl(subsys, c->vhost_wwpn);
	if (IS_ERR(ctrl)) {
		ret = -EINVAL;
		goto out_unlock;
	}
	n->cntlid = ctrl->cntlid;
	n->ctrl = ctrl;
	n->num_queues = subsys->max_qid + 1;
	ctrl->opaque = n;
	ctrl->start = nvmet_vhost_start_ctrl;
	ctrl->parse_extra_admin_cmd = nvmet_vhost_parse_admin_cmd;

	num_queues = ctrl->subsys->max_qid + 1;
	n->cqs = kzalloc(sizeof(*n->cqs) * num_queues, GFP_KERNEL);
	if (!n->cqs) {
		ret = -ENOMEM;
		goto out_ctrl_put;
	}
	n->sqs = kzalloc(sizeof(*n->sqs) * num_queues, GFP_KERNEL);
	if (!n->sqs) {
		ret = -ENOMEM;
		goto free_cqs;
	}

	n->eventfd = kmalloc(sizeof(struct nvmet_vhost_ctrl_eventfd)
				* num_queues, GFP_KERNEL);
	if (!n->eventfd) {
		ret = -ENOMEM;
		goto free_sqs;
	}

	mutex_unlock(&subsys->lock);
	return 0;

free_sqs:
	kfree(n->sqs);

free_cqs:
	kfree(n->cqs);

out_ctrl_put:
	nvmet_ctrl_put(ctrl);

out_unlock:
	mutex_unlock(&subsys->lock);
	return ret;
}

static int nvmet_vhost_set_eventfd(struct nvmet_vhost_ctrl *n, void __user *argp)
{
	struct nvmet_vhost_eventfd eventfd;
	int num;
	int ret;

	ret = copy_from_user(&eventfd, argp, sizeof(struct nvmet_vhost_eventfd));
	if (unlikely(ret))
		return ret;

	num = eventfd.num;
	if (num > n->ctrl->subsys->max_qid)
		return -EINVAL;

	n->eventfd[num].call = eventfd_fget(eventfd.fd);
	if (IS_ERR(n->eventfd[num].call))
		return -EBADF;
	n->eventfd[num].call_ctx = eventfd_ctx_fileget(n->eventfd[num].call);
	if (IS_ERR(n->eventfd[num].call_ctx)) {
		fput(n->eventfd[num].call);
		return -EBADF;
	}

	n->eventfd[num].irq_enabled = eventfd.irq_enabled;
	n->eventfd[num].vector = eventfd.vector;

	return 0;
}

static int nvmet_vhost_bar_read(struct nvmet_ctrl *ctrl, int offset, u64 *val)
{
	int status = NVME_SC_SUCCESS;

	switch(offset) {
	case NVME_REG_CAP:
		*val = ctrl->cap;
		break;
	case NVME_REG_CAP+4:
		*val = ctrl->cap >> 32;
	case NVME_REG_VS:
		*val = ctrl->subsys->ver;
		break;
	case NVME_REG_CC:
		*val = ctrl->cc;
		break;
	case NVME_REG_CSTS:
		*val = ctrl->csts;
		break;
	case NVME_REG_AQA:
		*val = (NVMET_VHOST_AQ_DEPTH - 1) |
		      (((NVMET_VHOST_AQ_DEPTH - 1) << 16));
		break;
	default:
		printk("Unknown offset: 0x%x\n", offset);
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		break;
	}

	return status;
}

static int nvmet_bar_write(struct nvmet_vhost_ctrl *n, int offset, u64 val)
{
	struct nvmet_ctrl *ctrl = n->ctrl;
	int status = NVME_SC_SUCCESS;

	switch(offset) {
	case NVME_REG_CC:
		nvmet_update_cc(ctrl, val);
		break;
	case NVME_REG_AQA:
		n->aqa = val & 0xffffffff;
		break;
	case NVME_REG_ASQ:
		n->asq = val;
		break;
	case NVME_REG_ASQ + 4:
		n->asq |= val << 32;
		break;
	case NVME_REG_ACQ:
		n->acq = val;
		break;
	case NVME_REG_ACQ + 4:
		n->acq |= val << 32;
		break;
	default:
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		break;
	}

	return status;
}

static int nvmet_vhost_bar_write(struct nvmet_vhost_ctrl *n, int offset, u64 val)
{
	if (offset < 0x1000)
		return nvmet_bar_write(n, offset, val);

	return -1;
}

static int nvmet_vhost_ioc_bar(struct nvmet_vhost_ctrl *n, void __user *argp)
{
	struct nvmet_vhost_bar bar;
	struct nvmet_vhost_bar __user *user_bar = argp;
	int ret = -EINVAL;

	ret = copy_from_user(&bar, argp, sizeof(bar));
	if (unlikely(ret))
		return ret;

	if (bar.type == VHOST_NVME_BAR_READ) {
		u64 val;
		ret = nvmet_vhost_bar_read(n->ctrl, bar.offset, &val);
		if (ret != NVME_SC_SUCCESS)
			return ret;
		ret = copy_to_user(&user_bar->val, &val, sizeof(u64));
	} else if (bar.type == VHOST_NVME_BAR_WRITE)
		ret = nvmet_vhost_bar_write(n, bar.offset, bar.val);

	return ret;
}

static int nvmet_vhost_open(struct inode *inode, struct file *f)
{
	struct nvmet_vhost_ctrl *n = kzalloc(sizeof(*n), GFP_KERNEL);

	if (!n)
		return -ENOMEM;

	/* We don't use virtqueue */
	vhost_dev_init(&n->dev, NULL, 0);
	f->private_data = n;

	return 0;
}

static void nvme_free_sq(struct nvmet_vhost_sq *sq,
		struct nvmet_vhost_ctrl *n)
{
	n->sqs[sq->sq.qid] = NULL;
	if (sq->sq.qid)
		kfree(sq);
}

static void nvme_free_cq(struct nvmet_vhost_cq *cq,
		struct nvmet_vhost_ctrl *n)
{
	n->cqs[cq->cq.qid] = NULL;
	if (cq->cq.qid)
		kfree(cq);
}

static void nvmet_vhost_clear_ctrl(struct nvmet_vhost_ctrl *n)
{
	int i;

	for (i = 0; i < n->num_queues; i++) {
		if (n->sqs[i] != NULL)
			nvme_free_sq(n->sqs[i], n);
	}
	for (i = 0; i < n->num_queues; i++) {
		if (n->cqs[i] != NULL)
			nvme_free_cq(n->cqs[i], n);
	}

	kfree(n->eventfd);
	kfree(n->cqs);
	kfree(n->sqs);
	nvmet_ctrl_put(n->ctrl);
}

static void nvmet_vhost_clear_eventfd(struct nvmet_vhost_ctrl *n)
{
	int i;

	for (i = 0; i < n->num_queues; i++) {
		if (n->eventfd[i].call_ctx) {
			eventfd_ctx_put(n->eventfd[i].call_ctx);
			fput(n->eventfd[i].call);
		}
	}
}

static int nvmet_vhost_release(struct inode *inode, struct file *f)
{
	struct nvmet_vhost_ctrl *n = f->private_data;

	nvmet_vhost_clear_eventfd(n);
	nvmet_vhost_clear_ctrl(n);

	vhost_dev_stop(&n->dev);
	vhost_dev_cleanup(&n->dev, false);

	kfree(n);
	return 0;
}

static long nvmet_vhost_ioctl(struct file *f, unsigned int ioctl,
			     unsigned long arg)
{
	struct nvmet_vhost_ctrl *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_NVME_SET_ENDPOINT:
	{
		struct vhost_nvme_target conf;
		if (copy_from_user(&conf, argp, sizeof(conf)))
			return -EFAULT;

		return nvmet_vhost_set_endpoint(n, &conf);
	}
	case VHOST_NVME_SET_EVENTFD:
		r = nvmet_vhost_set_eventfd(n, argp);
		return r;
	case VHOST_NVME_BAR:
		return nvmet_vhost_ioc_bar(n, argp);
	case VHOST_GET_FEATURES:
		features = VHOST_FEATURES;
		if (copy_to_user(featurep, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long nvmet_vhost_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return nvmet_vhost_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations nvmet_vhost_fops = {
	.owner          = THIS_MODULE,
	.release        = nvmet_vhost_release,
	.unlocked_ioctl = nvmet_vhost_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = nvmet_vhost_compat_ioctl,
#endif
	.open           = nvmet_vhost_open,
	.llseek		= noop_llseek,
};

static struct miscdevice nvmet_vhost_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-nvme",
	&nvmet_vhost_fops,
};

static int __init nvmet_vhost_init(void)
{
	return misc_register(&nvmet_vhost_misc);
}
module_init(nvmet_vhost_init);

static void nvmet_vhost_exit(void)
{
	misc_deregister(&nvmet_vhost_misc);
}
module_exit(nvmet_vhost_exit);

MODULE_AUTHOR("Ming Lin <ming.l@ssi.samsung.com>");
MODULE_LICENSE("GPL v2");

