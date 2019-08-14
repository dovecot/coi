AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE)

lib30_webpush_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib30_webpush_plugin.la

lib30_webpush_plugin_la_SOURCES = \
	webpush-plugin.c \
	webpush-subscription.c \
	webpush-subscription-parser.c \
	webpush-vapid.c

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	webpush-plugin.h \
	webpush-subscription.h \
	webpush-vapid.h

test_programs = \
	test-webpush-subscription-parser

noinst_PROGRAMS = $(test_programs)

test_webpush_subscription_parser_SOURCES = test-webpush-subscription-parser.c
test_webpush_subscription_parser_LDADD = webpush-subscription-parser.lo $(LIBDOVECOT)
test_webpush_subscription_parser_DEPENDENCIES = webpush-subscription-parser.lo $(LIBDOVECOT_DEPS)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
