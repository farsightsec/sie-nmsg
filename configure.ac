AC_PREREQ(2.60)
AC_INIT([sie-nmsg], [0.13])
AC_CONFIG_SRCDIR([nmsg_msg_sie.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

PKG_PROG_PKG_CONFIG
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([libwdns], [libwdns])

m4_sinclude(check_libnmsg.m4)

AC_OUTPUT
