AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-coi \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_SUBMISSION_INCLUDE)

lib11_submission_coi_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib11_submission_coi_plugin.la

lib11_submission_coi_plugin_la_SOURCES = \
	submission-coi-plugin.c

lib11_submission_coi_plugin_la_LIBADD = \
	$(top_builddir)/src/lib-coi/libdovecot-coi.la

noinst_HEADERS = \
	submission-coi-plugin.h
