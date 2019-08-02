#ifndef LMTP_COI_PLUGIN_H
#define LMTP_COI_PLUGIN_H

struct module;

extern const char *lmtp_coi_plugin_dependencies[];
extern const char lmtp_coi_plugin_binary_dependency[];

void lmtp_coi_plugin_init(struct module *module);
void lmtp_coi_plugin_deinit(void);

#endif
