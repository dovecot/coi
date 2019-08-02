AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-coi \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_DOVEADM_INCLUDE)

doveadm_moduledir = $(dovecot_moduledir)/doveadm

lib10_doveadm_coi_plugin_la_LDFLAGS = -module -avoid-version

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_coi_plugin.la

lib10_doveadm_coi_plugin_la_LIBADD = \
	$(top_builddir)/src/lib-coi/libdovecot-coi.la

lib10_doveadm_coi_plugin_la_SOURCES = \
	doveadm-coi-plugin.c

noinst_HEADERS = \
	doveadm-coi-plugin.h
