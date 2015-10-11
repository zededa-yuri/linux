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
#include <linux/blkdev.h>
#include <linux/module.h>
#include "nvmet.h"

static void nvmet_execute_get_error_log(struct nvmet_req *req)
{
	void *buf;

	/*
	 * We currently never set the More bit in the status field,
	 * so all error log entries are invalid and can be zeroed out.
	 * This is called a minum viable implementation (TM) of this
	 * mandatory log page.
	 */
	buf = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	memset(buf, 0, req->data_len);
	kunmap_atomic(buf);

	nvmet_req_complete(req, 0);
}

static void nvmet_execute_get_smart_log(struct nvmet_req *req)
{
	struct nvme_smart_log *log;

	/*
	 * XXX: fill out actual smart log
	 *
	 * We might have a hard time coming up with useful values for many
	 * of the fields, and even when we have useful data available
	 * (e.g. units or commands read/written) those aren't persistent
	 * over power loss.
	 */
	log = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	memset(log, 0, req->data_len);
	kunmap_atomic(log);

	nvmet_req_complete(req, 0);
}

static void nvmet_execute_get_fwslot_log(struct nvmet_req *req)
{
	void *buf;

	/*
	 * We only support a single firmware slot which always is active,
	 * so we can zero out the whole firmware slot log and still claim
	 * to fully implement this mandatory log page.
	 */
	buf = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	memset(buf, 0, req->data_len);
	kunmap_atomic(buf);

	nvmet_req_complete(req, 0);
}

static void nvmet_execute_identify_ctrl(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvme_id_ctrl *id;

	id = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	memset(id, 0, sizeof(*id));

	/* XXX: figure out how to assign real vendors IDs. */
	id->vid = 0;
	id->ssvid = 0;

	/* XXX: figure out real serial / model / revision values */
	memset(id->sn, ' ', sizeof(id->sn));
	memset(id->mn, ' ', sizeof(id->mn));
	memset(id->fr, ' ', sizeof(id->fr));
	strcpy((char *)id->mn, "Fake NVMe");

	id->rab = 6;

	/* XXX: figure out a real IEEE OUI */
	id->ieee[0] = 0x00;
	id->ieee[1] = 0x02;
	id->ieee[2] = 0xb3;

	/* we may have multiple controllers attached to the subsystem */
	id->mic = (1 << 1);

	/* no limit on data transfer sizes for now */
	id->mdts = 0;
	id->cntlid = cpu_to_le16(ctrl->cntlid);
	id->ver = cpu_to_le32(ctrl->subsys->ver);

	/* XXX: figure out what to do about RTD3R/RTD3 */

	id->oacs = 0;
	id->acl = 3;
	id->aerl = 3;

	/* first slot is read-only, only one slot supported */
	id->frmw = (1 << 0) | (1 << 1);
	id->lpa = 1 << 0;
#define NVMET_ERROR_LOG_SLOTS	128
	id->elpe = NVMET_ERROR_LOG_SLOTS - 1;
	id->npss = 0;

	id->sqes = (0x6 << 4) | 0x6;
	id->cqes = (0x4 << 4) | 0x4;
	id->nn = cpu_to_le32(ctrl->subsys->max_nsid);

	/* XXX: don't report vwc if the underlying device is write through */
	id->vwc = NVME_CTRL_VWC_PRESENT;

	/*
	 * We can't support atomic writes bigger than a LBA without support
	 * from the backend device.
	 */
	id->awun = 0;
	id->awupf = 0;

	/*
	 * We support SGLs, but nothing fancy.
	 */
	id->sgls = (1 << 0);

	/*
	 * Meh, we don't really support any power state.  Fake up the same
	 * values that qemu does.
	 */
	id->psd[0].max_power = cpu_to_le16(0x9c4);
	id->psd[0].entry_lat = cpu_to_le32(0x10);
	id->psd[0].exit_lat = cpu_to_le32(0x4);

	kunmap_atomic(id);

	nvmet_req_complete(req, 0);
}

static void nvmet_execute_identify_ns(struct nvmet_req *req)
{
	struct nvmet_ns *ns;
	struct nvme_id_ns *id;
	u16 status = 0;

	ns = nvmet_find_namespace(req->sq->ctrl, req->cmd->identify.nsid);
	if (!ns) {
		status = NVME_SC_INVALID_NS | NVME_SC_DNR;
		goto out;
	}

	id = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	memset(id, 0, sizeof(*id));

	/*
	 * nuse = ncap = nsze isn't aways true, but we have no way to find
	 * that out from the underlying device.
	 */
	id->ncap = id->nuse = id->nsze =
		cpu_to_le64(ns->size >> ns->blksize_shift);

	/*
	 * We just provide a single LBA format that matches what the
	 * underlying device reports.
	 */
	id->nlbaf = 0;
	id->flbas = 0;

	/*
	 * Our namespace might always be shared.  Not just with other
	 * controllers, but also with any other user of the block device.
	 */
	id->nmic = (1 << 0);

	/* XXX: provide a nguid value! */

	id->lbaf[0].ds = ns->blksize_shift;

	kunmap_atomic(id);

	nvmet_put_namespace(ns);
out:
	nvmet_req_complete(req, status);
}

static void nvmet_execute_identify_nslist(struct nvmet_req *req)
{
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvmet_ns *ns;
	u32 min_nsid = le32_to_cpu(req->cmd->identify.nsid);
	__le32 *list;
	int i = 0;

	list = kmap_atomic(sg_page(req->sg)) + req->sg->offset;
	rcu_read_lock();
	list_for_each_entry_rcu(ns, &ctrl->subsys->namespaces, dev_link) {
		if (ns->nsid <= min_nsid)
			continue;
		list[i++] = cpu_to_le32(ns->nsid);
		if (i == req->data_len / sizeof(__le32))
			goto out;
	}

	list[i] = 0;
out:
	rcu_read_unlock();
	kunmap_atomic(list);

	nvmet_req_complete(req, 0);
}

static void nvmet_execute_set_features(struct nvmet_req *req)
{
	struct nvmet_subsys *subsys = req->sq->ctrl->subsys;
	u32 cdw10 = le32_to_cpu(req->cmd->common.cdw10[0]);
	u16 status = 0;

	switch (cdw10 & 0xf) {
	case NVME_FEAT_NUM_QUEUES:
		nvmet_set_result(req,
			subsys->max_qid | (subsys->max_qid << 16));
		break;
	default:
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		break;
	}

	nvmet_req_complete(req, status);
}

static void nvmet_execute_get_features(struct nvmet_req *req)
{
	struct nvmet_subsys *subsys = req->sq->ctrl->subsys;
	u32 cdw10 = le32_to_cpu(req->cmd->common.cdw10[0]);
	u16 status = 0;

	switch (cdw10 & 0xf) {
	/*
	 * These features are mandatory in the spec, but we don't
	 * have a useful way to implement them.  We'll eventually
	 * need to come up with some fake values for these.
	 */
#if 0
	case NVME_FEAT_ARBITRATION:
		break;
	case NVME_FEAT_POWER_MGMT:
		break;
	case NVME_FEAT_TEMP_THRESH:
		break;
	case NVME_FEAT_ERR_RECOVERY:
		break;
	case NVME_FEAT_IRQ_COALESCE:
		break;
	case NVME_FEAT_IRQ_CONFIG:
		break;
	case NVME_FEAT_WRITE_ATOMIC:
		break;
	case NVME_FEAT_ASYNC_EVENT:
		break;
#endif
	case NVME_FEAT_VOLATILE_WC:
		nvmet_set_result(req, 1);
		break;
	case NVME_FEAT_NUM_QUEUES:
		nvmet_set_result(req,
			subsys->max_qid | (subsys->max_qid << 16));
		break;
	default:
		status = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		break;
	}

	nvmet_req_complete(req, status);
}

static inline u32 nvmet_get_log_page_len(struct nvme_command *cmd)
{
	u32 cdw10 = cmd->common.cdw10[0];

	return ((cdw10 >> 16) & 0xff) * sizeof(u32);
}

int nvmet_parse_admin_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	req->ns = NULL;

	switch (cmd->common.opcode) {
	case nvme_admin_get_log_page:
		req->data_len = nvmet_get_log_page_len(cmd);

		switch (cmd->common.cdw10[0] & 0xf) {
		case 0x01:
			req->execute = nvmet_execute_get_error_log;
			return 0;
		case 0x02:
			req->execute = nvmet_execute_get_smart_log;
			return 0;
		case 0x03:
			req->execute = nvmet_execute_get_fwslot_log;
			return 0;
		}
		break;
	case nvme_admin_identify:
		switch (cmd->identify.cns) {
		case 0x00:
			req->execute = nvmet_execute_identify_ns;
			req->data_len = sizeof(struct nvme_id_ns);
			return 0;
		case 0x01:
			req->execute = nvmet_execute_identify_ctrl;
			req->data_len = sizeof(struct nvme_id_ctrl);
			return 0;
		case 0x02:
			req->execute = nvmet_execute_identify_nslist;
			req->data_len = 4096;
			return 0;
		}
		break;
#if 0
	case nvme_admin_abort_cmd:
		req->execute = nvmet_execute_abort;
		req->data_len = 0;
		return 0;
#endif
	case nvme_admin_set_features:
		req->execute = nvmet_execute_set_features;
		req->data_len = 0;
		return 0;
	case nvme_admin_get_features:
		req->execute = nvmet_execute_get_features;
		req->data_len = 0;
		return 0;
#if 0
	case nvme_admin_async_event:
		req->exectute = nvmet_execute_aen;
		req->data = 0;
		return 0;
#endif
	}

	pr_err("nvmet: unhandled cmd %d\n", cmd->common.opcode);
	return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
}
