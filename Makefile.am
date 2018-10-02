BUILT_SOURCES =
EXTRA_DIST = COPYRIGHT LICENSE
CLEANFILES =
TESTS =
check_PROGRAMS =

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h
AM_CFLAGS = \
	$(my_CFLAGS) \
	$(libnmsg_CFLAGS) \
	$(libprotobuf_c_CFLAGS) \
	$(libwdns_CFLAGS)

MSG_LIBTOOL_FLAGS = -module -avoid-version

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

moduledir = $(libdir)/nmsg

nmsgsieincludedir = $(includedir)/nmsg/sie

nobase_nmsgsieinclude_HEADERS = \
	defs.h
nobase_nodist_nmsgsieinclude_HEADERS = \
	delay.pb-c.h \
	dnsdedupe.pb-c.h \
	dnsnx.pb-c.h \
	qr.pb-c.h \
	reputation.pb-c.h \
	newdomain.pb-c.h

# NOTE: if the nmsg msgmod version (nmsg_msgX) changes, it must be
# updated both here and in check_libnmsg.m4.

module_LTLIBRARIES = nmsg_msg9_sie.la

nmsg_msg9_sie_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(MSG_LIBTOOL_FLAGS)
nmsg_msg9_sie_la_LIBADD = \
	$(libnmsg_LIBS) \
	$(libwdns_LIBS)
nmsg_msg9_sie_la_SOURCES = nmsg_msg_sie.c
nodist_nmsg_msg9_sie_la_SOURCES = \
	delay.pb-c.c delay.pb-c.h \
	dnsdedupe.pb-c.c dnsdedupe.pb-c.h \
	dnsnx.pb-c.c dnsnx.pb-c.h \
	qr.pb-c.c qr.pb-c.h \
	reputation.pb-c.c reputation.pb-c.h \
	newdomain.pb-c.c newdomain.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_msg9_sie_la_SOURCES)
CLEANFILES += $(nodist_nmsg_msg9_sie_la_SOURCES)
EXTRA_DIST += \
	delay.c \
	delay.proto \
	dnsdedupe.c \
	dnsdedupe.proto \
	dnsnx.c \
	dnsnx.proto \
	qr.c \
	qr.proto \
	reputation.c \
	reputation.proto \
	newdomain.c \
	newdomain.proto

# Tests

TESTS_ENVIRONMENT = NMSG_MSGMOD_DIR=$(top_builddir)/.libs

TESTS += tests/test-parse
check_PROGRAMS += tests/test-parse
tests_test_parse_LDADD = $(libnmsg_LIBS)
tests_test_parse_SOURCES = tests/test-parse.c

TESTS += tests/test-misc
check_PROGRAMS += tests/test-misc
tests_test_misc_LDADD = $(libnmsg_LIBS)
tests_test_misc_SOURCES = tests/test-misc.c

TESTS += tests/test-io
check_PROGRAMS += tests/test-io
tests_test_io_LDADD = $(libnmsg_LIBS)
tests_test_io_SOURCES = tests/test-io.c
