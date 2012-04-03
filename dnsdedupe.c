/* SIE DNS dedupe nmsg message module */

/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include <string.h>
#include <time.h>

#include "defs.h"
#include "dnsdedupe.pb-c.c"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(dns_name_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_type_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_class_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rdata_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_message_print);
static NMSG_MSGMOD_FIELD_PRINTER(time_print);

/* Data. */

struct nmsg_msgmod_field dnsdedupe_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type"
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "count"
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "time_first",
		.print = time_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "time_last",
		.print = time_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "zone_time_first",
		.print = time_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "zone_time_last",
		.print = time_print
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "bailiwick",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rrname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrclass",
		.print = dns_class_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrtype",
		.print = dns_type_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "rrttl",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rdata",
		.flags = NMSG_MSGMOD_FIELD_REPEATED,
		.print = dns_rdata_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response",
		.print = dns_message_print
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_SIE,
	.msgtype	= { NMSG_VENDOR_SIE_DNSDEDUPE_ID, NMSG_VENDOR_SIE_DNSDEDUPE_NAME },

	.pbdescr	= &nmsg__sie__dns_dedupe__descriptor,
	.fields		= dnsdedupe_fields 
};

/* Private. */

static nmsg_res
time_print(nmsg_message_t msg,
	   struct nmsg_msgmod_field *field,
	   void *ptr,
	   struct nmsg_strbuf *sb,
	   const char *endline)
{
	nmsg_res res = nmsg_res_failure;
	time_t t;
	struct tm gm;

	t = *((uint32_t *) ptr);
	
	if (gmtime_r(&t, &gm) != NULL) {
		res = nmsg_strbuf_append(sb, "%s: %d-%02d-%02d %02d:%02d:%02d%s",
					 field->name,
					 1900 + gm.tm_year,
					 1 + gm.tm_mon,
					 gm.tm_mday,
					 gm.tm_hour,
					 gm.tm_min,
					 gm.tm_sec,
					 endline);
	}

	return (res);
}

static nmsg_res
dns_name_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	ProtobufCBinaryData *rrname = ptr;
	char name[WDNS_PRESLEN_NAME];
	nmsg_res res = nmsg_res_success;

	if (rrname->data != NULL &&
	    rrname->len > 0 &&
	    rrname->len <= WDNS_MAXLEN_NAME)
	{
		wdns_domain_to_str(rrname->data, rrname->len, name);
		res = nmsg_strbuf_append(sb, "%s: %s%s", field->name,
					 name, endline);
	}
	return (res);
}

static nmsg_res
dns_type_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	uint16_t rrtype;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrtype, ptr, sizeof(rrtype));
	s = wdns_rrtype_to_str(rrtype);
	res = nmsg_strbuf_append(sb, "%s: %s (%u)%s",
				 field->name,
				 s ? s : "<UNKNOWN>",
				 rrtype, endline);
	return (res);
}

static nmsg_res
dns_class_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	uint16_t rrclass;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrclass, ptr, sizeof(rrclass));
	s = wdns_rrclass_to_str(rrclass);
	res = nmsg_strbuf_append(sb, "%s: %s (%u)%s",
				 field->name,
				 s ? s : "<UNKNOWN>",
				 rrclass, endline);
	return (res);
}

static nmsg_res
dns_rdata_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field __attribute__((unused)),
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	Nmsg__Sie__DnsDedupe *dns = (Nmsg__Sie__DnsDedupe *) nmsg_message_get_payload(msg);
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;
	size_t bufsz;

	if (dns == NULL)
		return (nmsg_res_failure);

	if (dns->has_rrtype == false || dns->has_rrclass == false)
		return (nmsg_res_failure);

	buf = wdns_rdata_to_str(rdata->data, rdata->len, dns->rrtype, dns->rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (nmsg_res_success);

parse_error:
	free(buf);
	nmsg_strbuf_append(sb, "rdata: ### PARSE ERROR ###\n");
	return (nmsg_res_parse_error);
}

static nmsg_res
dns_message_print(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  void *ptr,
		  struct nmsg_strbuf *sb,
		  const char *endline)
{
	nmsg_res res;
	uint8_t *payload;
	size_t payload_len;

	res = nmsg_message_get_field(msg, field->name, 0, (void **) &payload, &payload_len);
	if (res == nmsg_res_success) {
		wdns_message_t dns;
		wdns_res wres;

		wres = wdns_parse_message(&dns, payload, payload_len);
		if (wres == wdns_res_success) {
			char *s;

			s = wdns_message_to_str(&dns);
			if (s != NULL) {
				nmsg_strbuf_append(sb, "%s: [%zd octets]%s%s---%s",
						   field->name, payload_len, endline, s, endline);
				free(s);
				wdns_clear_message(&dns);
				return (nmsg_res_success);
			}
			wdns_clear_message(&dns);
		}
	}
	nmsg_strbuf_append(sb, "%s: <PARSE ERROR>%s", field->name, endline);
	return (nmsg_res_success);
}
