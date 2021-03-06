AC_INIT([Dovecot COI], [0.1.0], [info@dovecot.fi], [dovecot-coi])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])

# Autoheader is not needed and does more harm than good for this package. However, it is
# tightly integrated in autoconf/automake and therefore it is difficult not to use it. As
# a workaround we give autoheader a dummy config header to chew on and we handle the
# real config header ourselves.
AC_CONFIG_HEADERS([dummy-config.h coi-autoconfig.h])

AC_DEFINE_UNQUOTED(COI_NAME, "$PACKAGE_NAME",
        [Define to the full name of Dovecot Chat over IMAP.])
AC_DEFINE_UNQUOTED(COIE_VERSION, "$PACKAGE_VERSION",
        [Define to the version of Dovecot Chat over IMAP.])

AC_ARG_ENABLE(unfinished,
AS_HELP_STRING([--enable-unfinished], [Enable unfinished code]),
	if test x$enableval = xyes; then
		CFLAGS="$CFLAGS -DBUILD_UNFINISHED=1"
		want_unfinished=yes
	fi)
AM_CONDITIONAL(BUILD_UNFINISHED, test "$want_unfinished" = "yes")

AM_INIT_AUTOMAKE([no-define foreign tar-ustar])
AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

DC_DOVECOT
DC_DOVECOT_MODULEDIR
LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"
LIBS="$DOVECOT_LIBS"
AC_SUBST(LIBDOVECOT_INCLUDE)

AC_CONFIG_FILES([
Makefile
src/Makefile
src/lib-coi/Makefile
src/doveadm-coi/Makefile
src/imap-coi/Makefile
src/lmtp-coi/Makefile
src/submission-coi/Makefile
src/webpush/Makefile
stamp.h])

AC_OUTPUT
