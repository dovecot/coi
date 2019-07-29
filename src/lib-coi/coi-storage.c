/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-context.h"
#include "mail-storage-private.h"
#include "coi-common.h"
#include "coi-storage.h"

#define COI_MAIL_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, coi_mail_user_module)
#define COI_MAIL_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, coi_mail_user_module)

struct coi_mail_user {
	union mail_user_module_context module_ctx;
	struct coi_context *coi_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(coi_mail_user_module,
                                  &mail_user_module_register);

struct coi_context *coi_get_user_context(struct mail_user *user)
{
	struct coi_mail_user *cuser = COI_MAIL_USER_CONTEXT_REQUIRE(user);

	return cuser->coi_ctx;
}

static void coi_user_deinit(struct mail_user *user)
{
	struct coi_mail_user *cuser = COI_MAIL_USER_CONTEXT_REQUIRE(user);

	coi_context_deinit(&cuser->coi_ctx);
	cuser->module_ctx.super.deinit(user);
}

static void coi_mail_user_created(struct mail_user *user)
{
	struct coi_mail_user *cuser;
	struct mail_user_vfuncs *v = user->vlast;

	if (user->autocreated) {
		/* don't set COI context for raw user */
		return;
	}

	cuser = p_new(user->pool, struct coi_mail_user, 1);
	cuser->module_ctx.super = *v;
	user->vlast = &cuser->module_ctx.super;
	v->deinit = coi_user_deinit;

	MODULE_CONTEXT_SET(user, coi_mail_user_module, cuser);
}

static void coi_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct coi_mail_user *cuser = COI_MAIL_USER_CONTEXT(user);

	/* coi_context_init() needs access to namespaces, so do it in this
	   hook instead of immediately when creating the user. */
	if (cuser != NULL)
		cuser->coi_ctx = coi_context_init(user);
}

static struct mail_storage_hooks coi_mail_storage_hooks = {
	.mail_user_created = coi_mail_user_created,
	.mail_namespaces_created = coi_mail_namespaces_created,
};

void coi_storage_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &coi_mail_storage_hooks);
}

void coi_storage_plugin_deinit(void)
{
	mail_storage_hooks_remove(&coi_mail_storage_hooks);
}
