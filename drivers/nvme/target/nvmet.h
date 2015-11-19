#ifndef _NVME_CMD_H
#define _NVME_CMD_H

#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/nvme.h>
#include <linux/configfs.h>
#include <linux/rcupdate.h>

struct nvmet_ns {
	struct list_head	dev_link;
	struct kref		ref;
	struct block_device	*bdev;
	u32			nsid;
	u32			blksize_shift;
	loff_t			size;

	struct nvmet_subsys	*subsys;
	const char		*device_path;

	struct config_group	device_group;
	struct config_group	default_groups[2];
	struct config_group	group;
	struct rcu_head		rcu;
};

static inline struct nvmet_ns *to_nvmet_ns(struct config_item *item)
{
	return container_of(to_config_group(item), struct nvmet_ns, group);
}

struct nvmet_cq {
	u16			qid;
	u16			size;
};

struct nvmet_sq {
	struct nvmet_ctrl	*ctrl;
	u16			qid;
	u16			size;
};

struct nvmet_ctrl {
	struct nvmet_subsys	*subsys;
	struct nvmet_cq		**cqs;
	struct nvmet_sq		**sqs;

	u64			cap;
	u32			cc;
	u32			csts;

	u16			cntlid;

	struct list_head	subsys_entry;
	struct kref		ref;
#define NVMET_SUBSYS_NAME_LEN		256
	char			subsys_name[NVMET_SUBSYS_NAME_LEN];

	void			*opaque;
	void			(*start)(void *);
};

struct nvmet_subsys {
	struct mutex		lock;

	struct list_head	namespaces;
	unsigned int		max_nsid;

	struct list_head	ctrls;
	struct ida		cntlid_ida;

	u16			max_qid;

	u64			ver;
	char			*subsys_name;

	struct list_head	entry;
	struct config_group	group;

	struct config_group	namespaces_group;
	struct config_group	controllers_group;
	struct config_group	*default_groups[3];
};

static inline struct nvmet_subsys *to_subsys(struct config_item *item)
{
	return container_of(to_config_group(item), struct nvmet_subsys, group);
}

static inline struct nvmet_subsys *namespaces_to_subsys(
		struct config_item *item)
{
	return container_of(to_config_group(item), struct nvmet_subsys,
			namespaces_group);
}

struct nvmet_req {
	struct nvme_command	*cmd;
	struct nvme_completion	*rsp;
	struct nvmet_sq		*sq;
	struct nvmet_cq		*cq;
	struct nvmet_ns		*ns;
	struct scatterlist	*sg;
	int			sg_cnt;
	size_t			data_len;

	void (*execute)(struct nvmet_req *req);
	void (*queue_response)(struct nvmet_req *req);
};

static inline void nvmet_set_status(struct nvmet_req *req, u16 status)
{
	req->rsp->status = cpu_to_le16(status << 1);
}

static inline void nvmet_set_result(struct nvmet_req *req, u32 result)
{
	req->rsp->result = cpu_to_le32(result);
}

static inline bool nvmet_is_write(struct nvmet_req *req)
{
	return req->cmd->common.opcode & 1;
}

/*
 * NVMe command writes actually are DMA reads for us on the target side.
 */
static inline enum dma_data_direction
nvmet_data_dir(struct nvmet_req *cmd)
{
	return nvmet_is_write(cmd) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;
}

int nvmet_parse_io_cmd(struct nvmet_req *req);
int nvmet_parse_admin_cmd(struct nvmet_req *req);

u16 nvmet_req_init(struct nvmet_req *req, struct nvmet_cq *cq,
		struct nvmet_sq *sq,
		void (*queue_response)(struct nvmet_req *req));
void nvmet_req_complete(struct nvmet_req *req, u16 status);

void nvmet_cq_init(struct nvmet_ctrl *ctrl, struct nvmet_cq *cq, u16 qid,
		u16 size);
void nvmet_sq_init(struct nvmet_ctrl *ctrl, struct nvmet_sq *sq, u16 qid,
		u16 size);
void nvmet_sq_destroy(struct nvmet_sq *sq);

void nvmet_update_cc(struct nvmet_ctrl *ctrl, u32 new);
struct nvmet_ctrl *nvmet_alloc_ctrl(struct nvmet_subsys *subsys,
		const char *subsys_name);
struct nvmet_ctrl *nvmet_ctrl_find_get(struct nvmet_subsys *subsys, u16 cntlid);
void nvmet_ctrl_put(struct nvmet_ctrl *ctrl);

struct nvmet_subsys *nvmet_find_subsys(char *subsys_name);
struct nvmet_subsys *nvmet_subsys_alloc(const char *subsys_name);
void nvmet_subsys_free(struct nvmet_subsys *subsys);

struct nvmet_ns *nvmet_find_namespace(struct nvmet_ctrl *ctrl, __le32 nsid);
void nvmet_put_namespace(struct nvmet_ns *ns);
int nvmet_ns_enable(struct nvmet_ns *ns, const char *path);
struct nvmet_ns *nvmet_ns_alloc(struct nvmet_subsys *subsys, u32 nsid);
void nvmet_ns_free(struct nvmet_ns *ns);

#define NVMET_QUEUE_SIZE	1024
#define NVMET_NR_QUEUES		64

int __init nvmet_init_configfs(void);
void __exit nvmet_exit_configfs(void);

#endif /* _NVME_CMD_H */
