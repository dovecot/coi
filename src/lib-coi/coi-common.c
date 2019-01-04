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
};

struct coi_context *
coi_context_init(struct mail_user *user)
{
	struct coi_context *coi_ctx;
	pool_t pool;

	pool = pool_alloconly_create("coi context", 2048);
	coi_ctx = p_new(pool, struct coi_context, 1);
	coi_ctx->pool = pool;
	coi_ctx->user = user;

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
