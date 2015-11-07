/*
 * Copyright (c) 2015 HGST, a Western Digital Company.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/scatterlist.h>
#include <linux/delay.h>
#include <linux/blk-mq.h>
#include <linux/nvme.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/t10-pi.h>
#include "nvmet.h"
#include "../host/nvme.h"

#define NVME_LOOP_MAX_Q_DEPTH		1024
#define NVME_LOOP_AQ_DEPTH		256

#define NVME_LOOP_MAX_SEGMENTS		32

struct nvme_loop_ctrl {
	spinlock_t		lock;
	struct nvme_loop_queue	*queues;
	u32			queue_count;
	size_t			queue_size;

	struct blk_mq_tag_set	admin_tag_set;

	u16			cntlid;
	char			*subsys_name;

	struct list_head	list;
	u64			cap;
	struct blk_mq_tag_set	tag_set;
	struct nvme_ctrl	ctrl;

	struct nvmet_ctrl	*target_ctrl;
};

static inline struct nvme_loop_ctrl *to_loop_ctrl(struct nvme_ctrl *ctrl)
{
	return container_of(ctrl, struct nvme_loop_ctrl, ctrl);
}

struct nvme_loop_queue {
	struct nvmet_cq		nvme_cq;
	struct nvmet_sq		nvme_sq;
	struct nvme_loop_ctrl	*ctrl;
};

struct nvme_loop_iod {
	struct scatterlist	sg[NVME_LOOP_MAX_SEGMENTS];
	struct nvme_command	cmd;
	struct nvme_completion	rsp;
	struct nvmet_req	req;
	struct work_struct	work;
};

static int nr_io_queues;
module_param(nr_io_queues, int, 0444);
MODULE_PARM_DESC(nr_io_queues,
	 "Number of I/O queues.  Default is one per CPU");

static LIST_HEAD(nvme_loop_ctrl_list);
static DEFINE_MUTEX(nvme_loop_ctrl_mutex);

static inline int nvme_loop_queue_idx(struct nvme_loop_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static void nvme_loop_complete_rq(struct request *req)
{
	int error = 0;

	if (unlikely(req->errors)) {
		if (nvme_req_needs_retry(req, req->errors)) {
			nvme_requeue_req(req);
			return;
		}

		if (req->cmd_type == REQ_TYPE_DRV_PRIV)
			error = req->errors;
		else
			error = nvme_error_status(req->errors);
	}

	blk_mq_end_request(req, error);
}

static void nvme_loop_queue_response(struct nvmet_req *nvme_req)
{
	struct nvme_loop_iod *iod =
		container_of(nvme_req, struct nvme_loop_iod, req);
	struct nvme_completion *cqe = &iod->rsp;
	struct request *req = blk_mq_rq_from_pdu(iod);

	if (req->cmd_type == REQ_TYPE_DRV_PRIV)
		req->special = (void *)(uintptr_t)le32_to_cpu(cqe->result);
	blk_mq_complete_request(req, le16_to_cpu(cqe->status) >> 1);
}

static void nvme_loop_execute_work(struct work_struct *work)
{
	struct nvme_loop_iod *iod =
		container_of(work, struct nvme_loop_iod, work);

	iod->req.execute(&iod->req);
}

static int nvme_loop_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct nvme_ns *ns = hctx->queue->queuedata;
	struct nvme_loop_queue *queue = hctx->driver_data;
	struct request *req = bd->rq;
	struct nvme_loop_iod *iod = blk_mq_rq_to_pdu(req);
	int ret;

	switch (req->cmd_type) {
	case REQ_TYPE_FS:
		if (req->cmd_flags & REQ_FLUSH)
			nvme_setup_flush(ns, &iod->cmd);
		else
			nvme_setup_rw(ns, req, &iod->cmd);
		break;
	case REQ_TYPE_DRV_PRIV:
		memcpy(&iod->cmd, req->cmd, sizeof(struct nvme_command));
		break;
	default:
		return BLK_MQ_RQ_QUEUE_ERROR;
	}

	ret = nvmet_req_init(&iod->req, &queue->nvme_cq, &queue->nvme_sq,
			nvme_loop_queue_response);
	if (ret)
		goto out_err;

	if (blk_rq_bytes(req)) {
		sg_init_table(iod->sg, req->nr_phys_segments);

		iod->req.sg = iod->sg;
		iod->req.sg_cnt = blk_rq_map_sg(req->q, req, iod->sg);
		BUG_ON(iod->req.sg_cnt > req->nr_phys_segments);
	}

	iod->cmd.common.command_id = req->tag;
	blk_mq_start_request(req);

	schedule_work(&iod->work);
	return 0;
out_err:
	return BLK_MQ_RQ_QUEUE_ERROR;
}

static int __nvme_loop_init_request(struct nvme_loop_ctrl *ctrl,
		struct request *req, unsigned int queue_idx)
{
	struct nvme_loop_iod *iod = blk_mq_rq_to_pdu(req);

	BUG_ON(queue_idx >= ctrl->queue_count);

	iod->req.cmd = &iod->cmd;
	iod->req.rsp = &iod->rsp;
	INIT_WORK(&iod->work, nvme_loop_execute_work);
	return 0;
}

static int nvme_loop_init_request(void *data, struct request *req,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return __nvme_loop_init_request(data, req, hctx_idx + 1);
}

static int nvme_loop_init_admin_request(void *data, struct request *req,
				unsigned int hctx_idx, unsigned int rq_idx,
				unsigned int numa_node)
{
	return __nvme_loop_init_request(data, req, 0);
}

static int nvme_loop_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_loop_ctrl *ctrl = data;
	struct nvme_loop_queue *queue = &ctrl->queues[hctx_idx + 1];

	BUG_ON(hctx_idx >= ctrl->queue_count);

	hctx->driver_data = queue;
	return 0;
}

static int nvme_loop_init_admin_hctx(struct blk_mq_hw_ctx *hctx, void *data,
		unsigned int hctx_idx)
{
	struct nvme_loop_ctrl *ctrl = data;
	struct nvme_loop_queue *queue = &ctrl->queues[0];

	BUG_ON(hctx_idx != 0);

	hctx->driver_data = queue;
	return 0;
}

static struct blk_mq_ops nvme_loop_mq_ops = {
	.queue_rq	= nvme_loop_queue_rq,
	.complete	= nvme_loop_complete_rq,
	.map_queue	= blk_mq_map_queue,
	.init_request	= nvme_loop_init_request,
	.init_hctx	= nvme_loop_init_hctx,
};

static struct blk_mq_ops nvme_loop_admin_mq_ops = {
	.queue_rq	= nvme_loop_queue_rq,
	.complete	= nvme_loop_complete_rq,
	.map_queue	= blk_mq_map_queue,
	.init_request	= nvme_loop_init_admin_request,
	.init_hctx	= nvme_loop_init_admin_hctx,
};

static void nvme_loop_destroy_admin_queue(struct nvme_loop_ctrl *ctrl)
{
	blk_cleanup_queue(ctrl->ctrl.admin_q);
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
	nvme_shutdown_ctrl(&ctrl->ctrl);
	/* disconnect queue */
}

static void nvme_loop_free_ctrl(struct nvme_ctrl *nctrl)
{
	struct nvme_loop_ctrl *ctrl = to_loop_ctrl(nctrl);

	list_del(&ctrl->list);
#if 0
	for (i = 1; i < ctrl->queue_count; i++)
		/* disconnect queue */
#endif
	blk_mq_free_tag_set(&ctrl->tag_set);
	nvme_loop_destroy_admin_queue(ctrl);
	kfree(ctrl->queues);
	kfree(ctrl->subsys_name);
	kfree(ctrl);
}

static int nvme_loop_init_queue(struct nvme_loop_ctrl *ctrl, int idx,
		size_t queue_size)
{
	struct nvme_loop_queue *queue;
	struct nvmet_subsys *subsys;
	struct nvmet_ctrl *target_ctrl = NULL;
	u16 qid, cntlid;
	int ret = 0;

	queue = &ctrl->queues[idx];
	queue->ctrl = ctrl;
	
	qid = nvme_loop_queue_idx(queue);
	cntlid = qid ? ctrl->cntlid : 0xffff;

	subsys = nvmet_find_subsys(ctrl->subsys_name);
	if (!subsys) {
		pr_warn("connect request for invalid subsystem!\n");
		return -EINVAL;
	}

	mutex_lock(&subsys->lock);
	target_ctrl = nvmet_ctrl_find_get(subsys, cntlid);
	if (target_ctrl) {
		pr_info("adding queue %d to ctrl %d.\n",
			qid, target_ctrl->cntlid);
	} else {
		BUG_ON(qid != 0);

		target_ctrl = nvmet_alloc_ctrl(subsys, ctrl->subsys_name);
		if (IS_ERR(target_ctrl)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		pr_info("creating controller %d.\n", target_ctrl->cntlid);
	}

	nvmet_cq_init(target_ctrl, &queue->nvme_cq, qid,
			qid ? ctrl->queue_size : NVME_LOOP_AQ_DEPTH);
	nvmet_sq_init(target_ctrl, &queue->nvme_sq, qid,
			qid ? ctrl->queue_size : NVME_LOOP_AQ_DEPTH);
	if (!qid)
		ctrl->cntlid = target_ctrl->cntlid;

	if (!ctrl->target_ctrl)
		ctrl->target_ctrl = target_ctrl;

out_unlock:
	mutex_unlock(&subsys->lock);
	return ret;
}

static int nvme_loop_configure_admin_queue(struct nvme_loop_ctrl *ctrl)
{
	unsigned page_shift = PAGE_SHIFT;
	unsigned dev_page_min, dev_page_max;
	int error;

	error = nvme_loop_init_queue(ctrl, 0, NVME_LOOP_AQ_DEPTH);
	if (error) {
		dev_err(ctrl->ctrl.dev,
			"failed to initialize admin queue: %d\n", error);
		return error;
	}

	error = ctrl->ctrl.ops->reg_read64(&ctrl->ctrl, NVME_REG_CAP,
			&ctrl->cap);
	if (error) {
		dev_err(ctrl->ctrl.dev,
			"prop_get NVME_REG_CAP failed\n");
		return error;
	}

	dev_page_min = NVME_CAP_MPSMIN(ctrl->cap) + 12;
	if (page_shift < dev_page_min) {
		dev_err(ctrl->ctrl.dev,
			"Minimum device page size (%u) too large for "
			"host (%u)\n", 1 << dev_page_min, 1 << page_shift);
		return -ENODEV;
	}

	dev_page_max = NVME_CAP_MPSMAX(ctrl->cap) + 12;
	if (page_shift > dev_page_max) {
		dev_info(ctrl->ctrl.dev,
			"Device maximum page size (%u) smaller than "
			"host (%u); enabling work-around\n",
			1 << dev_page_max, 1 << page_shift);
		page_shift = dev_page_max;
	}

	ctrl->queue_size =
		min_t(int, NVME_CAP_MQES(ctrl->cap) + 1, NVME_LOOP_MAX_Q_DEPTH);

	error = nvme_enable_ctrl(&ctrl->ctrl, ctrl->cap, page_shift);
	if (error)
		return error;

	memset(&ctrl->admin_tag_set, 0, sizeof(ctrl->admin_tag_set));
	ctrl->admin_tag_set.ops = &nvme_loop_admin_mq_ops;
	ctrl->admin_tag_set.queue_depth = NVME_LOOP_AQ_DEPTH;
	ctrl->admin_tag_set.numa_node = NUMA_NO_NODE;
	ctrl->admin_tag_set.cmd_size = sizeof(struct nvme_loop_iod);
	ctrl->admin_tag_set.driver_data = ctrl;
	ctrl->admin_tag_set.nr_hw_queues = 1;
	ctrl->admin_tag_set.timeout = ADMIN_TIMEOUT;

	error = blk_mq_alloc_tag_set(&ctrl->admin_tag_set);
	if (error)
		goto out_disable;

	ctrl->ctrl.admin_q = blk_mq_init_queue(&ctrl->admin_tag_set);
	if (IS_ERR(ctrl->ctrl.admin_q)) {
		error = PTR_ERR(ctrl->ctrl.admin_q);
		goto out_free_tagset;
	}
	ctrl->ctrl.admin_q->queuedata = ctrl;

	return 0;

out_free_tagset:
	blk_mq_free_tag_set(&ctrl->admin_tag_set);
out_disable:
	nvme_shutdown_ctrl(&ctrl->ctrl);
	return error;
}

static int nvme_loop_reg_read32(struct nvme_ctrl *ctrl, u32 off, u32 *val)
{
	struct nvmet_ctrl *target_ctrl = to_loop_ctrl(ctrl)->target_ctrl;

	switch (off) {
	case NVME_REG_VS:
		*val = target_ctrl->subsys->ver;
		return 0;
	case NVME_REG_CSTS:
		*val = target_ctrl->csts;
		return 0;
	default:
		return -EINVAL;
	}
}

static int nvme_loop_reg_read64(struct nvme_ctrl *ctrl, u32 off, u64 *val)
{
	struct nvmet_ctrl *target_ctrl = to_loop_ctrl(ctrl)->target_ctrl;

	switch (off) {
	case NVME_REG_CAP:
		*val = target_ctrl->cap;
		return 0;
	default:
		return -EINVAL;
	}
}

static int nvme_loop_reg_write32(struct nvme_ctrl *ctrl, u32 off, u32 val)
{
	struct nvmet_ctrl *target_ctrl = to_loop_ctrl(ctrl)->target_ctrl;

	switch (off) {
	case NVME_REG_CC:
		nvmet_update_cc(target_ctrl, val);
		return 0;
	default:
		return -EINVAL;
	}
}

static bool nvme_loop_io_incapable(struct nvme_ctrl *ctrl)
{
	/* XXX: */
	return false;
}

static int nvme_loop_reset_ctrl(struct nvme_ctrl *ctrl)
{
	return -EIO;
}

static const struct nvme_ctrl_ops nvme_loop_ctrl_ops = {
	.reg_read32		= nvme_loop_reg_read32,
	.reg_read64		= nvme_loop_reg_read64,
	.reg_write32		= nvme_loop_reg_write32,
	.io_incapable		= nvme_loop_io_incapable,
	.reset_ctrl		= nvme_loop_reset_ctrl,
	.free_ctrl		= nvme_loop_free_ctrl,
};

enum {
	NVME_OPT_ERR		= 0,
	NVME_OPT_NAME		= 1 << 2,
	NVME_OPT_REQUIRED	=
	NVME_OPT_NAME,
};

static const match_table_t opt_tokens = {
	{ NVME_OPT_NAME,	"name=%s"	},
	{ NVME_OPT_ERR,		NULL		}
};

static int nvme_loop_parse_options(const char *buf, struct nvme_loop_ctrl *ctrl)
{
	substring_t args[MAX_OPT_ARGS];
	char *options, *p, *o;
	int token, ret = 0;
	unsigned opt_mask = 0;

	o = options = kstrdup(buf, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	while ((p = strsep(&options, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, opt_tokens, args);
		opt_mask |= token;
		switch (token) {
		case NVME_OPT_NAME:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			ctrl->subsys_name = p;
			break;
		default:
			pr_warn("unknown parameter or missing value '%s' in ctrl creation request\n",
				p);
			ret = -EINVAL;
			goto out;
		}
	}

	if ((opt_mask & NVME_OPT_REQUIRED) != NVME_OPT_REQUIRED) {
		int i;

		for (i = 0; i < ARRAY_SIZE(opt_tokens); i++) {
			if ((opt_tokens[i].token & NVME_OPT_REQUIRED) &&
			    !(opt_tokens[i].token & opt_mask)) {
				pr_warn("nvmf: missing parameter '%s'\n",
					opt_tokens[i].pattern);
			}
		}

		ret = -EINVAL;
	}

out:
	kfree(o);
	return ret;
}

static ssize_t
nvme_loop_create_ctrl(struct device *sysfs_dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct nvme_loop_ctrl *ctrl;
	int ret, i;

	ctrl = kzalloc(sizeof(*ctrl), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	ret = nvme_init_ctrl(&ctrl->ctrl, sysfs_dev, &nvme_loop_ctrl_ops,
				0 /* no vendor.. */,
				0 /* no quirks, we're perfect! */);
	if (ret)
		goto out_free_ctrl;

	ret = nvme_loop_parse_options(buf, ctrl);
	if (ret)
		goto out_uninit_ctrl;

	spin_lock_init(&ctrl->lock);

	ret = -ENOMEM;
	ctrl->queue_count = 1; /* admin queue */;
	if (nr_io_queues > 0)
		ctrl->queue_count += nr_io_queues;
	else
		ctrl->queue_count += num_possible_cpus();

	ctrl->queues = kcalloc(ctrl->queue_count,
			sizeof(*ctrl->queues), GFP_KERNEL);
	if (!ctrl->queues)
		goto out_uninit_ctrl;

	ret = nvme_loop_configure_admin_queue(ctrl);
	if (ret)
		goto out_kfree_queues;

	ret = nvme_set_queue_count(&ctrl->ctrl, ctrl->queue_count - 1);
	if (ret <= 0) {
		dev_err(ctrl->ctrl.dev,
			"set_queue_count failed: %d\n", ret);
		goto out_remove_admin_queue;
	}

	if (ret <= ctrl->queue_count)
		ctrl->queue_count = ret + 1;

	dev_info(ctrl->ctrl.dev,
		"creating %d I/O queues.\n", ctrl->queue_count - 1);

	for (i = 1; i < ctrl->queue_count; i++) {
		ret = nvme_loop_init_queue(ctrl, i, ctrl->queue_size);
		if (ret) {
			dev_err(ctrl->ctrl.dev,
				"failed to initialize I/O queue: %d\n", ret);
			goto out_remove_admin_queue;
		}
	}

	memset(&ctrl->tag_set, 0, sizeof(ctrl->tag_set));
	ctrl->tag_set.ops = &nvme_loop_mq_ops;
	ctrl->tag_set.queue_depth = ctrl->queue_size;
	ctrl->tag_set.numa_node = NUMA_NO_NODE;
	ctrl->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ctrl->tag_set.cmd_size = sizeof(struct nvme_loop_iod);
	ctrl->tag_set.driver_data = ctrl;
	ctrl->tag_set.nr_hw_queues = ctrl->queue_count - 1;
	ctrl->tag_set.timeout = NVME_IO_TIMEOUT;
	ctrl->ctrl.tagset = &ctrl->tag_set;

	ret = blk_mq_alloc_tag_set(&ctrl->tag_set);
	if (ret)
		goto out_free_tag_set;

	ret = nvme_init_identify(&ctrl->ctrl);
	if (ret)
		goto out_free_queues;

	ctrl->ctrl.max_segments = NVME_LOOP_MAX_SEGMENTS;

	nvme_scan_namespaces(&ctrl->ctrl);

	pr_info("new ctrl: \"%s\"\n", ctrl->subsys_name);

	mutex_lock(&nvme_loop_ctrl_mutex);
	list_add_tail(&ctrl->list, &nvme_loop_ctrl_list);
	mutex_unlock(&nvme_loop_ctrl_mutex);
	return count;

out_free_tag_set:
	blk_mq_free_tag_set(&ctrl->tag_set);
out_free_queues:
#if 0
	for (i = 1; i < ctrl->queue_count; i++)
		/* disconnect queue */
#endif
out_remove_admin_queue:
	nvme_loop_destroy_admin_queue(ctrl);
out_kfree_queues:
	kfree(ctrl->queues);
out_uninit_ctrl:
	nvme_uninit_ctrl(&ctrl->ctrl);
out_free_ctrl:
	kfree(ctrl);
	return ret;
}

static DEVICE_ATTR(add_ctrl, S_IWUSR, NULL, nvme_loop_create_ctrl);

static void __nvme_loop_remove_ctrl(struct nvme_loop_ctrl *ctrl)
{
	nvme_remove_namespaces(&ctrl->ctrl);
	nvme_uninit_ctrl(&ctrl->ctrl);
	nvme_put_ctrl(&ctrl->ctrl);
}

static struct class *nvme_loop_class;
static struct device *nvme_loop_device;

static int __init nvme_loop_init_module(void)
{
	int ret = -ENOMEM;

	nvme_loop_class = class_create(THIS_MODULE, "nvme-loop");
	if (IS_ERR(nvme_loop_class)) {
		pr_err("couldn't register class nvme-loop\n");
		ret = PTR_ERR(nvme_loop_class);
		goto out;
	}

	nvme_loop_device =
		device_create(nvme_loop_class, NULL, MKDEV(0, 0), NULL, "ctl");
	if (IS_ERR(nvme_loop_device)) {
		pr_err("couldn't create nvme-loop device!\n");
		ret = PTR_ERR(nvme_loop_device);
		goto out_destroy_class;
	}

	ret = device_create_file(nvme_loop_device, &dev_attr_add_ctrl);
	if (ret) {
		pr_err("couldn't add device attr.\n");
		goto out_destroy_device;
	}

	return 0;

out_destroy_device:
	device_destroy(nvme_loop_class, MKDEV(0, 0));
out_destroy_class:
	class_destroy(nvme_loop_class);
out:
	return ret;
}

static void __exit nvme_loop_cleanup_module(void)
{
	struct nvme_loop_ctrl *ctrl;

	mutex_lock(&nvme_loop_ctrl_mutex);
	while (!list_empty(&nvme_loop_ctrl_list)) {
		ctrl = list_entry(nvme_loop_ctrl_list.next,
				struct nvme_loop_ctrl, list);

		if (!list_empty(&ctrl->list))
			list_del(&ctrl->list);

		__nvme_loop_remove_ctrl(ctrl);
	}
	mutex_unlock(&nvme_loop_ctrl_mutex);

	device_destroy(nvme_loop_class, MKDEV(0, 0));
	class_destroy(nvme_loop_class);
}

module_init(nvme_loop_init_module);
module_exit(nvme_loop_cleanup_module);

MODULE_LICENSE("GPL v2");
