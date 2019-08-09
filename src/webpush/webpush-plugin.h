#ifndef WEBPUSH_PLUGIN_H
#define WEBPUSH_PLUGIN_H 1

struct module;

#define MAILBOX_ATTRIBUTE_WEBPUSH_PREFIX "webpush/"

void webpush_plugin_init(struct module *module);
void webpush_plugin_deinit(void);

#endif
