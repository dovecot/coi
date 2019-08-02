AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-coi \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_IMAP_INCLUDE)

lib11_imap_coi_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib11_imap_coi_plugin.la

lib11_imap_coi_plugin_la_LIBADD = \
	$(top_builddir)/src/lib-coi/libdovecot-coi.la

lib11_imap_coi_plugin_la_SOURCES = \
	imap-coi-plugin.c \
	imap-coi-storage.c

noinst_HEADERS = \
	imap-coi-plugin.h
