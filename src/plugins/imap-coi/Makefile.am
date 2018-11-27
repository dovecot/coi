AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_IMAP_INCLUDE)

imap_moduledir = $(moduledir)

lib11_imap_coi_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib11_imap_coi_plugin.la

lib11_imap_coi_plugin_la_SOURCES = \
	imap-coi-plugin.c

noinst_HEADERS = \
	imap-coi-plugin.h
