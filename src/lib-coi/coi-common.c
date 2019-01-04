/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"

#include "coi-common.h"

/*
 * COI context
 */

struct coi_context {
	pool_t pool;

	struct mail_user *user;

	const char *root_box_name;
	struct mail_namespace *root_ns;
};

struct coi_context *
coi_context_init(struct mail_user *user)
{
	struct coi_context *coi_ctx;
	struct mail_namespace *ns;
	pool_t pool;
	const char *root_box_name;

	pool = pool_alloconly_create("coi context", 2048);
	coi_ctx = p_new(pool, struct coi_context, 1);
	coi_ctx->pool = pool;
	coi_ctx->user = user;

	root_box_name = mail_user_plugin_getenv(user, COI_SETTING_MAILBOX_ROOT);
	if (root_box_name == NULL) {
		ns = mail_namespace_find_inbox(user->namespaces);

		root_box_name = t_strconcat(ns->prefix,
					    COI_MAILBOX_DEFAULT_ROOT, NULL);
	} else {
		ns = mail_namespace_find(user->namespaces, root_box_name);
	}
	coi_ctx->root_box_name = p_strdup(pool, root_box_name);
	coi_ctx->root_ns = ns;

	return coi_ctx;
}

void coi_context_deinit(struct coi_context **_coi_ctx)
{
	struct coi_context *coi_ctx = *_coi_ctx;

	*_coi_ctx = NULL;

	if (coi_ctx == NULL)
		return;

	pool_unref(&coi_ctx->pool);
}

const char *coi_get_mailbox_root(struct coi_context *coi_ctx)
{
	return coi_ctx->root_box_name;
}
