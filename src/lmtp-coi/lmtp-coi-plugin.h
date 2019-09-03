#ifndef LMTP_COI_PLUGIN_H
#define LMTP_COI_PLUGIN_H

struct module;
struct coi_context;

extern const char *lmtp_coi_plugin_dependencies[];
extern const char lmtp_coi_plugin_binary_dependency[];

int lmtp_coi_message_filter_save_chat(struct coi_context *coi_ctx,
				      struct mail *src_mail,
				      const struct smtp_address *mail_from,
				      const char **client_error_r);
void lmtp_coi_message_filter_init(struct module *module);
void lmtp_coi_message_filter_deinit(void);

void lmtp_coi_plugin_init(struct module *module);
void lmtp_coi_plugin_deinit(void);

#endif
