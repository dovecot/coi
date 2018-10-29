AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_SUBMISSION_INCLUDE)

submission_moduledir = $(moduledir)

lib11_submission_coi_plugin_la_LDFLAGS = -module -avoid-version

submission_module_LTLIBRARIES = \
	lib11_submission_coi_plugin.la

lib11_submission_coi_plugin_la_SOURCES = \
	submission-coi-plugin.c

noinst_HEADERS = \
	submission-coi-plugin.h
