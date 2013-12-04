AC_PREREQ(2.60)
AC_INIT([sie-nmsg], [0.14])
AC_CONFIG_SRCDIR([nmsg_msg_sie.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

PKG_PROG_PKG_CONFIG

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

PKG_CHECK_MODULES([libnmsg], [libnmsg])
PKG_CHECK_MODULES([libwdns], [libwdns])

MY_CHECK_LIBPROTOBUF_C
MY_CHECK_LIBNMSG_MSGMOD

AC_OUTPUT
