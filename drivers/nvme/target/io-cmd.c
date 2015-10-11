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

static void nvmet_bio_done(struct bio *bio)
{
	nvmet_req_complete(bio->bi_private,
		bio->bi_error ? NVME_SC_INTERNAL | NVME_SC_DNR : 0);
	bio_put(bio);
}

static void nvmet_execute_rw(struct nvmet_req *req)
{
	int sg_cnt = req->sg_cnt;
	struct scatterlist *sg;
	struct bio *bio;
	sector_t sector;
	int rw, i;

	if (!req->sg_cnt) {
		nvmet_req_complete(req, 0);
		return;
	}

	if (req->cmd->rw.opcode == nvme_cmd_write) {
		if (req->cmd->rw.control & cpu_to_le16(NVME_RW_FUA))
			rw = WRITE_FUA;
		else
			rw = WRITE;
	} else {
		rw = READ;
	}

	sector = le64_to_cpu(req->cmd->rw.slba);
	sector <<= (req->ns->blksize_shift - 9);

	bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
	bio->bi_bdev = req->ns->bdev;
	bio->bi_iter.bi_sector = sector;
	bio->bi_private = req;
	bio->bi_end_io = nvmet_bio_done;

	for_each_sg(req->sg, sg, req->sg_cnt, i) {
		if (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
				!= sg->length) {
			struct bio *prev = bio;

			bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
			bio->bi_bdev = req->ns->bdev;
			bio->bi_iter.bi_sector = sector;

			bio_chain(bio, prev);
			submit_bio(rw, prev);
		}

		sector += sg->length >> 9;
		sg_cnt--;
	}

	submit_bio(rw, bio);
}

static void nvmet_execute_flush(struct nvmet_req *req)
{
	struct bio *bio = bio_alloc(GFP_KERNEL, 0);

	bio->bi_bdev = req->ns->bdev;
	bio->bi_private = req;
	bio->bi_end_io = nvmet_bio_done;

	submit_bio(WRITE_FLUSH, bio);
}

int nvmet_parse_io_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	req->ns = nvmet_find_namespace(req->sq->ctrl, cmd->rw.nsid);
	if (!req->ns)
		return NVME_SC_INVALID_NS | NVME_SC_DNR;

	switch (cmd->common.opcode) {
	case nvme_cmd_read:
		req->execute = nvmet_execute_rw;
		req->data_len = ((u32)le16_to_cpu(cmd->rw.length) + 1) <<
				req->ns->blksize_shift;
		return 0;
	case nvme_cmd_write:
		req->execute = nvmet_execute_rw;
		req->data_len = ((u32)le16_to_cpu(cmd->rw.length) + 1) <<
				req->ns->blksize_shift;
		return 0;
	case nvme_cmd_flush:
		req->execute = nvmet_execute_flush;
		req->data_len = 0;
		return 0;
	default:
		pr_err("nvmet: unhandled cmd %d\n", cmd->common.opcode);
		return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}
}
