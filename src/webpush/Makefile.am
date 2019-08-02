AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE)

lib05_webpush_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib05_webpush_plugin.la

lib05_webpush_plugin_la_SOURCES = \
	webpush-plugin.c

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	webpush-plugin.h
