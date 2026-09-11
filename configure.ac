AC_PREREQ(2.64)
AC_INIT([sie-nmsg],
        [1.3.1],
        [https://github.com/farsightsec/sie-nmsg/issues],
        [sie-nmsg],
        [https://github.com/farsightsec/sie-nmsg])
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

PKG_CHECK_MODULES([libnmsg], [libnmsg >= 1.0.0])
PKG_CHECK_MODULES([libwdns], [libwdns >= 0.8.0])

PKG_CHECK_MODULES([libprotobuf_c], [libprotobuf-c >= 1.0.1])
AC_PATH_PROG([PROTOC_C], [protoc-c])
AS_IF([test -z "$PROTOC_C"],
      [AC_MSG_ERROR([The protoc-c program was not found. Please install the protobuf-c compiler!])])

MY_CHECK_LIBNMSG_MSGMOD

AC_OUTPUT
