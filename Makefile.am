MSG_LIBTOOL_FLAGS = -module -avoid-version

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

.proto.pb-c.h:
	protoc-c --c_out="`dirname $@`" $<

moduledir = $(libdir)/nmsg

nmsgsieincludedir = $(includedir)/nmsg/sie

nobase_nmsgsieinclude_HEADERS = \
	defs.h \
	dnsdedupe.pb-c.h \
	qr.pb-c.h \
	reputation.pb-c.h

EXTRA_DIST = \
	dnsdedupe.c \
	dnsdedupe.pb-c.c \
	dnsdedupe.pb-c.h \
	dnsdedupe.proto \
	qr.c \
	qr.pb-c.c \
	qr.pb-c.h \
	qr.proto \
	reputation.c \
	reputation.pb-c.c \
	reputation.pb-c.h \
	reputation.proto

# NOTE: if the nmsg msgmod version (nmsg_msgX) changes, it must be
# updated both here and in check_libnmsg.m4.

module_LTLIBRARIES = nmsg_msg8_sie.la

nmsg_msg8_sie_la_CFLAGS = \
	@libnmsg_cflags@
nmsg_msg8_sie_la_LDFLAGS = \
	$(MSG_LIBTOOL_FLAGS) \
	@libnmsg_ldflags@
nmsg_msg8_sie_la_LIBADD = -lwdns
nmsg_msg8_sie_la_SOURCES = nmsg_msg_sie.c

dep: dnsdedupe.pb-c.c qr.pb-c.c reputation.pb-c.c

.PHONY: dep
