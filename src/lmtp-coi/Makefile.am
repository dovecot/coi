AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-coi \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_LMTP_INCLUDE)

lib11_lmtp_coi_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib11_lmtp_coi_plugin.la

lib11_lmtp_coi_plugin_la_LIBADD = \
	$(top_builddir)/src/lib-coi/libdovecot-coi.la

lib11_lmtp_coi_plugin_la_SOURCES = \
	lmtp-coi-message-filter.c \
	lmtp-coi-plugin.c

noinst_HEADERS = \
	lmtp-coi-plugin.h
