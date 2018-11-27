#ifndef IMAP_COI_PLUGIN_H
#define IMAP_COI_PLUGIN_H

struct module;

extern const char *imap_coi_plugin_dependencies[];
extern const char imap_coi_plugin_binary_dependency[];

void imap_coi_plugin_init(struct module *module);
void imap_coi_plugin_deinit(void);

#endif
