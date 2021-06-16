#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>
#include <scsi/scsi_common.h>
#include <scsi/scsi_proto.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include "vhost_nvme_base.h"
#include "vhost_nvme_fabric.h"

int vhost_nvme_check_true(struct se_portal_group *se_tpg)
{
	return 1;
}

int vhost_nvme_check_false(struct se_portal_group *se_tpg)
{
	return 0;
}

char *vhost_nvme_get_fabric_wwn(struct se_portal_group *se_tpg)
{
	struct vhost_nvme_tpg *tpg = container_of(se_tpg,
				struct vhost_nvme_tpg, se_tpg);
	struct vhost_nvme_tport *tport = tpg->tport;

	return &tport->tport_name[0];
}

u16 vhost_nvme_get_tag(struct se_portal_group *se_tpg)
{
	struct vhost_nvme_tpg *tpg = container_of(se_tpg,
				struct vhost_nvme_tpg, se_tpg);
	return tpg->tport_tpgt;
}

u32 vhost_nvme_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	return 1;
}

void vhost_nvme_release_cmd(struct se_cmd *se_cmd)
{
	return;
}

u32 vhost_nvme_sess_get_index(struct se_session *se_sess)
{
	return 0;
}

int vhost_nvme_write_pending(struct se_cmd *se_cmd)
{
	return 0;
}

void vhost_nvme_set_default_node_attrs(struct se_node_acl *nacl)
{
	return;
}

int vhost_nvme_get_cmd_state(struct se_cmd *se_cmd)
{
	return 0;
}

int vhost_nvme_queue_data_in(struct se_cmd *se_cmd)
{
	return 0;
}

int vhost_nvme_queue_status(struct se_cmd *se_cmd)
{
	return 0;
}

void vhost_nvme_queue_tm_rsp(struct se_cmd *se_cmd)
{
	return;
}

void vhost_nvme_aborted_task(struct se_cmd *se_cmd)
{
	return;
}

