#include <linux/module.h>

static int __init nvmet_vhost_init(void)
{
	return 0;
}
module_init(nvmet_vhost_init);

static void nvmet_vhost_exit(void)
{
}
module_exit(nvmet_vhost_exit);

MODULE_AUTHOR("Ming Lin <ming.l@ssi.samsung.com>");
MODULE_LICENSE("GPL v2");

