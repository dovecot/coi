/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "settings-parser.h"
#include "smtp-address.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "coi-common.h"
#include "coi-contact.h"
#include "coi-secret.h"
#include "doveadm-coi-plugin.h"

#include <time.h>

static void coi_cmd_help(const struct doveadm_cmd_ver2 *cmd);

static const char *coi_normalize_address(const char *str, const char *name)
{
	struct smtp_address *addr;
	const char *error;

	if (smtp_address_parse_mailbox(pool_datastack_create(), str,
				       SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL,
				       &addr, &error) < 0)
		i_fatal("Invalid %s: %s", name, error);
	return coi_normalize_smtp_address(addr);
}

static const char *coi_get_normalized_hash(const char *from, const char *to)
{
	return coi_contact_generate_hash(coi_normalize_address(from, "from"),
					 coi_normalize_address(to, "to"));
}

static void cmd_coi_hash_generate(struct doveadm_cmd_context *cctx)
{
	const char *from, *to;
	bool normalize;

	if (!doveadm_cmd_param_str(cctx, "from", &from))
		coi_cmd_help(cctx->cmd);
	if (!doveadm_cmd_param_str(cctx, "to", &to))
		to = NULL;

	if (doveadm_cmd_param_bool(cctx, "normalize", &normalize) && normalize) {
		from = coi_normalize_address(from, "from");
		if (to != NULL)
			to = coi_normalize_address(to, "to");
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("hash", "hash", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	doveadm_print(coi_contact_generate_hash(from, to));
}

static const char *coi_settings_get_secret(const char *set_name)
{
	const char *value = doveadm_plugin_getenv(set_name);
	if (value == NULL || value[0] == '\0')
		i_fatal("%s setting is empty and --secret parameter not used", set_name);
	return t_strcut(value, ' ');
}

static void cmd_coi_token_generate(struct doveadm_cmd_context *cctx)
{
	const char *secret, *expires_str, *from, *to, *error;
	struct coi_token *token;
	bool temp;

	token = coi_token_new(pool_datastack_create());
	token->create_time = time(NULL);

	if (!doveadm_cmd_param_str(cctx, "from", &from) ||
	    !doveadm_cmd_param_str(cctx, "to", &to))
		coi_cmd_help(cctx->cmd);

	if (!doveadm_cmd_param_str(cctx, "secret", &secret)) {
		if (doveadm_cmd_param_bool(cctx, "temp", &temp) && temp)
			secret = coi_settings_get_secret(COI_SETTING_TOKEN_TEMP_SECRETS);
		else
			secret = coi_settings_get_secret(COI_SETTING_TOKEN_PERM_SECRETS);
	}

	if (!doveadm_cmd_param_str(cctx, "expires", &expires_str))
		token->validity_secs = COI_PERM_TOKEN_VALIDITY_SECS;
	else if (settings_get_time(expires_str, &token->validity_secs, &error) < 0)
		i_fatal("Invalid expires: %s", error);

	token->from_to_normalized_hash = coi_get_normalized_hash(from, to);
	token->secret = "";

	string_t *str = t_str_new(128);
	coi_token_append(str, token);
	coi_secret_append(str, str_c(str), secret);

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("token", "token", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	doveadm_print(str_c(str));
}

static void cmd_coi_token_verify(struct doveadm_cmd_context *cctx)
{
	const char *secret, *from, *to, *token_string, *hash, *str, *error;
	struct coi_secret_settings secret_set;
	struct coi_token *token;
	time_t now;
	bool valid, temp;
	const char *result = NULL;

	i_zero(&secret_set);

	if (!doveadm_cmd_param_str(cctx, "token", &token_string))
		coi_cmd_help(cctx->cmd);

	if (!doveadm_cmd_param_str(cctx, "time", &str))
		now = time(NULL);
	else {
		if (str_to_time(str, &now) < 0)
			i_fatal("Invalid time parameter: '%s'", str);
	}

	if (!doveadm_cmd_param_str(cctx, "from", &from))
		from = NULL;
	if (!doveadm_cmd_param_str(cctx, "to", &to))
		to = NULL;
	if ((from == NULL) != (to == NULL)) /* neither or both */
		coi_cmd_help(cctx->cmd);

	if (doveadm_cmd_param_str(cctx, "secret", &secret)) {
		coi_secret_settings_init(&secret_set, pool_datastack_create(),
					 NULL, secret);
	} else {
		secret = NULL;
		coi_secret_settings_init(&secret_set, pool_datastack_create(),
					 doveadm_plugin_getenv(COI_SETTING_TOKEN_TEMP_SECRETS),
					 doveadm_plugin_getenv(COI_SETTING_TOKEN_PERM_SECRETS));
	}

	/* verify whether the token matches secrets */
	if (coi_token_parse(token_string, pool_datastack_create(),
			    &token, &error) < 0)
		i_fatal("Invalid token: %s", error);

	valid = coi_token_verify_quick(&secret_set, now, token, &temp, &error);
	if (!valid)
		result = t_strdup_printf("Failed to verify token: %s", error);
	else if (secret != NULL)
		result = "Token matches given secret";
	else if (temp)
		result = "Token matches a temporary secret";
	else
		result = "Token matches a permanent secret";

	if (from != NULL && to != NULL && valid) {
		hash = coi_get_normalized_hash(from, to);
		if (strcmp(hash, token->from_to_normalized_hash) != 0) {
			result = t_strconcat(result,
				", but doesn't match given from/to address pair", NULL);
			valid = FALSE;
		} else {
			result = t_strconcat(result,
				" and given from/to address pair", NULL);
		}
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("result", "result", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	doveadm_print(result);
	if (!valid)
		doveadm_exit_code = 1;
}

static struct doveadm_cmd_ver2 doveadm_coi_commands[] = {
{
	.name = "coi hash generate",
	.usage = "[--normalize] <from> [<to>]",
        .cmd = cmd_coi_hash_generate,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "normalize", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "from", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "to", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "coi token generate",
	.usage = "[--temp | --secret <secret>] [--expires <time>] <from> <to>",
        .cmd = cmd_coi_token_generate,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "temp", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "secret", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "expires", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "from", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "to", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "coi token verify",
	.usage = "[--secret <secret>] [--time <unix timestamp>] <token> [<from> <to>]",
        .cmd = cmd_coi_token_verify,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "secret", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "time", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "token", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "from", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "to", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
};

static void coi_cmd_help(const struct doveadm_cmd_ver2 *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_coi_commands); i++) {
		if (doveadm_coi_commands[i].cmd == cmd->cmd)
			help_ver2(&doveadm_coi_commands[i]);
	}
	i_unreached();
}

void doveadm_coi_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_coi_commands); i++)
		doveadm_cmd_register_ver2(&doveadm_coi_commands[i]);
}

void doveadm_coi_plugin_deinit(void)
{
}
