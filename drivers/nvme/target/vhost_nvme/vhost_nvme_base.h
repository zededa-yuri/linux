#define VHOST_NVME_VERSION  "v0.1"
#define VHOST_NVME_NAMELEN 32

struct vhost_nvme_tpg {
	/* iSCSI target portal group tag for TCM */
	u16 tport_tpgt;
	/* Pointer back to vhost_nvme_tport */
	struct vhost_nvme_tport *tport;
	/* Returned by vhost_nvme_make_tpg() */
	struct se_portal_group se_tpg;
};

struct vhost_nvme_tport {
	/* ASCII formatted TargetName for IQN */
	char tport_name[VHOST_NVME_NAMELEN];
	/* Returned by vhost_nvme_make_tport() */
	struct se_wwn tport_wwn;
};
