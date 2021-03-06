/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "coi-common.h"
#include "coi-config.h"
#include "imap-metadata.h"
#include "mail-storage-private.h"
#include "mailbox-attribute-private.h"

#define COI_CONTEXT_CONFIG_CACHE_SECS (60*60)

struct coi_config_cache {
	time_t last_updated;
	struct coi_config config;
};

static const char *filter_names[COI_CONFIG_FILTER_SEEN+1] = {
	"none",
	"active",
	"seen",
};

bool coi_config_filter_parse(const char *str, enum coi_config_filter *filter_r)
{
	enum coi_config_filter filter;

	for (filter = COI_CONFIG_FILTER_NONE; filter <= COI_CONFIG_FILTER_SEEN; filter++) {
		if (strcmp(filter_names[filter], str) == 0) {
			*filter_r = filter;
			return TRUE;
		}
	}
	return FALSE;
}

static int
coi_metadata_get(struct imap_metadata_transaction *trans, const char *attr_key,
		 const char **value_r)
{
	const char *key =
		t_strconcat(IMAP_METADATA_PRIVATE_PREFIX"/", attr_key, NULL);
	struct mail_attribute_value value;
	enum mail_error error;
	int ret;

	ret = imap_metadata_get(trans, key, &value);
	switch (ret) {
	case -1:
		i_error("coi: Failed to get %s metadata: %s", key,
			imap_metadata_transaction_get_last_error(trans, &error));
		break;
	case 0:
		*value_r = NULL;
		break;
	case 1:
		*value_r = value.value;
		break;
	default:
		i_unreached();
	}
	return ret;
}

static int
coi_config_read_settings(struct imap_metadata_transaction *trans,
			 struct coi_config *config_r)
{
	const char *value;
	int ret;

	if ((ret = coi_metadata_get(trans, MAILBOX_ATTRIBUTE_COI_CONFIG_MESSAGE_FILTER,
				    &value)) < 0)
		return -1;
	if (ret > 0) {
		if (!coi_config_filter_parse(value, &config_r->filter)) {
			/* invalid value - use the default */
		}
	}
	return 0;
}

int coi_config_read(struct coi_context *coi_ctx, struct coi_config *config_r)
{
	struct imap_metadata_transaction *trans;
	const char *client_error, *value;
	enum mail_error error;
	int ret;

	i_zero(config_r);
	if (coi_ctx->config_cache != NULL &&
	    ioloop_time - coi_ctx->config_cache->last_updated < COI_CONTEXT_CONFIG_CACHE_SECS) {
		*config_r = coi_ctx->config_cache->config;
		return 0;
	}

	trans = imap_metadata_transaction_begin_server(coi_ctx->user);
	ret = coi_metadata_get(trans, MAILBOX_ATTRIBUTE_COI_CONFIG_ENABLED, &value);
	if (ret > 0 && strcmp(value, "yes") == 0) {
		/* COI is enabled. Read the config further. Ignore any invalid
		   configuration settings. */
		config_r->enabled = TRUE;
		ret = coi_config_read_settings(trans, config_r);
	}

	(void)imap_metadata_transaction_commit(&trans, &error, &client_error);
	if (ret == 0) {
		if (coi_ctx->config_cache == NULL)
			coi_ctx->config_cache = p_new(coi_ctx->pool, struct coi_config_cache, 1);
		coi_ctx->config_cache->last_updated = ioloop_time;
		coi_ctx->config_cache->config = *config_r;
	}
	return ret;
}

int coi_config_set_enabled(struct mail_user *user, bool set)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_attribute_value value = {
		.value = set ? "yes" : NULL,
	};
	int ret = 0;

	box = mailbox_alloc(ns->list, "INBOX", 0);
	if (mailbox_open(box) < 0) {
		i_error("coi: Can't set enabled metadata: "
			"Failed to open INBOX: %s",
			mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return -1;
	}
	t = mailbox_transaction_begin(box, 0, "coi metadata change");
	if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				  MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER
				  MAILBOX_ATTRIBUTE_COI_CONFIG_ENABLED, &value) < 0) {
		i_error("coi: Can't set enabled metadata: %s",
			mailbox_get_last_internal_error(t->box, NULL));
		ret = -1;
		mailbox_transaction_rollback(&t);
	} else if (mailbox_transaction_commit(&t) < 0) {
		i_error("coi: Can't commit enabled metadata: %s",
			mailbox_get_last_internal_error(t->box, NULL));
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
coi_create_missing_mailbox(struct mail_user *user, const char *base_name,
			   bool subscribe)
{
	struct coi_context *coi_ctx = coi_get_user_context(user);
	struct mailbox *box;
	const char *name = coi_mailbox_get_name(coi_ctx, base_name);
	int ret;

	box = mailbox_alloc(coi_ctx->root_ns->list, name, 0);
	mailbox_set_reason(box, "Enabling COI autocreates");
	if ((ret = mailbox_create(box, NULL, FALSE)) < 0) {
		enum mail_error error;
		const char *errstr = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_EXISTS)
			ret = 0;
		else
			i_error("coi: Failed to create mailbox %s: %s", name, errstr);
	} else if (!subscribe)
		;
	else if ((ret = mailbox_set_subscribed(box, TRUE)) < 0) {
		i_error("coi: Failed to subscribe to mailbox %s: %s", name,
			mailbox_get_last_error(box, NULL));
	}
	mailbox_free(&box);
	return ret;
}

static int coi_create_missing_mailboxes(struct mail_user *user)
{
	if (coi_create_missing_mailbox(user, COI_MAILBOX_CONTACTS, FALSE) < 0)
		return -1;
	if (coi_create_missing_mailbox(user, COI_MAILBOX_CHATS, TRUE) < 0)
		return -1;
	return 0;
}

static int
coi_attribute_config_enabled_set(struct mailbox_transaction_context *t,
				 const char *key ATTR_UNUSED,
				 const struct mail_attribute_value *value)
{
	const char *str;

	if (mailbox_attribute_value_to_string(t->box->storage, value, &str) < 0)
		return -1;
	if (str == NULL) {
		return 0;
	} else if (strcmp(str, "yes") == 0) {
		if (coi_create_missing_mailboxes(t->box->storage->user) < 0)
			return -1;
	} else {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
			"Invalid enabled value. Must be yes or NIL.");
		return -1;
	}
	return 0;
}

static int
coi_attribute_config_message_filter(struct mailbox_transaction_context *t,
				    const char *key ATTR_UNUSED,
				    const struct mail_attribute_value *value)
{
	const char *str;
	enum coi_config_filter filter;

	if (mailbox_attribute_value_to_string(t->box->storage, value, &str) < 0)
		return -1;
	if (!coi_config_filter_parse(str, &filter)) {
		mail_storage_set_error(t->box->storage, MAIL_ERROR_PARAMS,
				       "Invalid message-filter value");
		return -1;
	}
	return 0;
}

static int
coi_attribute_config_mailbox_root(struct mailbox *box,
				  const char *key ATTR_UNUSED,
				  struct mail_attribute_value *value_r)
{
	struct coi_context *coi_ctx = coi_get_user_context(box->storage->user);

	value_r->value = coi_get_mailbox_root(coi_ctx);
	return 1;
}

static const struct mailbox_attribute_internal
iattr_coi_config_enabled = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER
		MAILBOX_ATTRIBUTE_COI_CONFIG_ENABLED,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.set = coi_attribute_config_enabled_set
};

static const struct mailbox_attribute_internal
iattr_coi_config_message_filter = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER
		MAILBOX_ATTRIBUTE_COI_CONFIG_MESSAGE_FILTER,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.set = coi_attribute_config_message_filter
};

static const struct mailbox_attribute_internal
iattr_coi_config_mailbox_root = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER
		MAILBOX_ATTRIBUTE_COI_CONFIG_MAILBOX_ROOT,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,
	.flags = MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED,

	.get = coi_attribute_config_mailbox_root
};

void coi_config_global_init(void)
{
	static bool initialized = FALSE;

	if (initialized)
		return;
	initialized = TRUE;

	mailbox_attribute_register_internal(&iattr_coi_config_enabled);
	mailbox_attribute_register_internal(&iattr_coi_config_message_filter);
	mailbox_attribute_register_internal(&iattr_coi_config_mailbox_root);
}
