AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	-DMODULEDIR=\""$(dovecot_moduledir)"\"

dovecot_pkglib_LTLIBRARIES = libdovecot-coi.la

libdovecot_coi_la_DEPENDENCIES = \
	$(LIBDOVECOT_DEPS)
libdovecot_coi_la_LIBADD = \
	$(LIBDOVECOT)

libdovecot_coi_la_SOURCES =

headers = \
	coi-common.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
