AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-coi \
	$(LIBDOVECOT_INCLUDE) \
	$(LIBDOVECOT_STORAGE_INCLUDE) \
	$(LIBDOVECOT_PUSH_NOTIFICATION_INCLUDE)

lib30_webpush_plugin_la_LDFLAGS = -module -avoid-version

dovecot_module_LTLIBRARIES = \
	lib30_webpush_plugin.la

lib30_webpush_plugin_la_SOURCES = \
	webpush-message.c \
	webpush-notify.c \
	webpush-plugin.c \
	webpush-send.c \
	webpush-subscription.c \
	webpush-subscription-parser.c \
	webpush-vapid.c \
	webpush-payload.c

lib30_webpush_plugin_la_LIBADD = \
	$(top_builddir)/src/lib-coi/libdovecot-coi.la

pkginc_libdir=$(dovecot_pkgincludedir)
pkginc_lib_HEADERS = \
	webpush-message.h \
	webpush-notify.h \
	webpush-plugin.h \
	webpush-send.h \
	webpush-subscription.h \
	webpush-vapid.h \
	webpush-payload.h

noinst_HEADERS = \
	webpush-payload-private.h

test_programs = \
	test-webpush-message \
	test-webpush-subscription-parser \
	test-webpush-payload

test_libs = \
	$(LIBDOVECOT) \
	$(LIBDOVECOT_STORAGE)

test_deps = \
	$(LIBDOVECOT_DEPS) \
	$(LIBDOVECOT_STORAGE_DEPS)

noinst_PROGRAMS = $(test_programs)

test_webpush_subscription_parser_SOURCES = test-webpush-subscription-parser.c
test_webpush_subscription_parser_LDADD = webpush-subscription-parser.lo $(LIBDOVECOT)
test_webpush_subscription_parser_DEPENDENCIES = webpush-subscription-parser.lo $(LIBDOVECOT_DEPS)

test_webpush_message_SOURCES = test-webpush-message.c
test_webpush_message_LDADD = webpush-message.lo $(LIBDOVECOT)
test_webpush_message_DEPENDENCIES = webpush-message.lo $(LIBDOVECOT_DEPS)

test_webpush_payload_SOURCES = test-webpush-payload.c
test_webpush_payload_LDADD = $(test_libs) \
			     webpush-subscription-parser.lo \
			     webpush-payload.lo
test_webpush_payload_DEPENDENCIES = webpush-subscription-parser.lo \
				    webpush-payload.lo \
				    $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
