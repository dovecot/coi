#ifndef SUBMISSION_COI_PLUGIN_H
#define SUBMISSION_COI_PLUGIN_H

struct module;

extern const char *submission_coi_plugin_dependencies[];
extern const char submission_coi_plugin_binary_dependency[];

void submission_coi_plugin_init(struct module *module);
void submission_coi_plugin_deinit(void);

#endif
