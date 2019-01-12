#include "core/private.h"

int lws_plat_apply_FD_CLOEXEC(int n)
{
	return 0;
}

void TEE_GenerateRandom(void *randomBuffer, uint32_t randomBufferLen);

uint64_t
lws_time_in_microseconds(void)
{
	return ((unsigned long long)time(NULL)) * 1000000;
}
#if 0
int
lws_get_random(struct lws_context *context, void *buf, int len)
{
	TEE_GenerateRandom(buf, len);

	return len;
}
#endif

#if 0
void lwsl_emit_syslog(int level, const char *line)
{
	IMSG("%d: %s\n", level, line);
}
#endif

void
lws_plat_drop_app_privileges(const struct lws_context_creation_info *info)
{
}

int
lws_plat_context_early_init(void)
{
	return 0;
}

void
lws_plat_context_early_destroy(struct lws_context *context)
{
}

void
lws_plat_context_late_destroy(struct lws_context *context)
{
#if defined(LWS_WITH_NETWORK)
	if (context->lws_lookup)
		lws_free(context->lws_lookup);
#endif
}

lws_fop_fd_t
_lws_plat_file_open(const struct lws_plat_file_ops *fops,
		    const char *filename, const char *vpath, lws_fop_flags_t *flags)
{
	return NULL;
}

int
_lws_plat_file_close(lws_fop_fd_t *fop_fd)
{
	return 0;
}

lws_fileofs_t
_lws_plat_file_seek_cur(lws_fop_fd_t fop_fd, lws_fileofs_t offset)
{
	return 0;
}

 int
_lws_plat_file_read(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
		    uint8_t *buf, lws_filepos_t len)
{

	return 0;
}

 int
_lws_plat_file_write(lws_fop_fd_t fop_fd, lws_filepos_t *amount,
		     uint8_t *buf, lws_filepos_t len)
{

	return 0;
}


int
lws_plat_init(struct lws_context *context,
	      const struct lws_context_creation_info *info)
{
#if defined(LWS_WITH_NETWORK)
	/* master context has the global fd lookup array */
	context->lws_lookup = lws_zalloc(sizeof(struct lws *) *
					 context->max_fds, "lws_lookup");
	if (context->lws_lookup == NULL) {
		lwsl_err("OOM on lws_lookup array for %d connections\n",
			 context->max_fds);
		return 1;
	}

	lwsl_notice(" mem: platform fd map: %5lu bytes\n",
		    (long)sizeof(struct lws *) * context->max_fds);
#endif
#ifdef LWS_WITH_PLUGINS
	if (info->plugin_dirs)
		lws_plat_plugins_init(context, info->plugin_dirs);
#endif

	return 0;
}

int
lws_plat_write_file(const char *filename, void *buf, int len)
{
	return 1;
}

int
lws_plat_read_file(const char *filename, void *buf, int len)
{
	return -1;
}

int
lws_plat_recommended_rsa_bits(void)
{
	return 4096;
}
