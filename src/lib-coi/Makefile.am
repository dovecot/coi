AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_SERVICE_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	-DMODULEDIR=\""$(dovecot_moduledir)"\"

dovecot_pkglib_LTLIBRARIES = libdovecot-coi.la

libdovecot_coi_la_DEPENDENCIES = \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)
libdovecot_coi_la_LIBADD = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)

libdovecot_coi_la_SOURCES = \
	coi-common.c

headers = \
	coi-common.h

pkginc_libdir=$(dovecot_pkgincludedir)
pkginc_lib_HEADERS = $(headers)
