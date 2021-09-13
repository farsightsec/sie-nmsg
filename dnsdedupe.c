/* SIE DNS dedupe nmsg message module */

/*
 * Copyright (c) 2010-2015, 2020-2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include <string.h>
#include <time.h>

#include "defs.h"
#include "dnsdedupe.pb-c.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(dns_name_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_type_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_class_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rdata_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_message_print);
static NMSG_MSGMOD_FIELD_PRINTER(time_print);

static NMSG_MSGMOD_FIELD_FORMATTER(dns_name_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_type_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_class_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_rdata_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_message_format);
static NMSG_MSGMOD_FIELD_FORMATTER(time_format);

static NMSG_MSGMOD_FIELD_PARSER(dns_name_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_type_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_class_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_rdata_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_message_parse);
static NMSG_MSGMOD_FIELD_PARSER(time_parse);

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
		.print = time_print,
		.format = time_format,
		.parse = time_parse
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "time_last",
		.print = time_print,
		.format = time_format,
		.parse = time_parse
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "zone_time_first",
		.print = time_print,
		.format = time_format,
		.parse = time_parse
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "zone_time_last",
		.print = time_print,
		.format = time_format,
		.parse = time_parse
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "bailiwick",
		.print = dns_name_print,
		.format = dns_name_format,
		.parse = dns_name_parse
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rrname",
		.print = dns_name_print,
		.format = dns_name_format,
		.parse = dns_name_parse
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrclass",
		.print = dns_class_print,
		.format = dns_class_format,
		.parse = dns_class_parse
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrtype",
		.print = dns_type_print,
		.format = dns_type_format,
		.parse = dns_type_parse
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "rrttl",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rdata",
		.flags = NMSG_MSGMOD_FIELD_REPEATED,
		.print = dns_rdata_print,
		.format = dns_rdata_format,
		.parse = dns_rdata_parse
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response",
		.print = dns_message_print,
		.format = dns_message_format,
		.parse = dns_message_parse
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
	(void)msg; /* unused parameter */
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
time_format(nmsg_message_t m,
	    struct nmsg_msgmod_field *field,
	    void *ptr,
	    struct nmsg_strbuf *sb,
	    const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	nmsg_res res = nmsg_res_failure;
	time_t t;
	struct tm gm;

	t = *((uint32_t *) ptr);

	if (gmtime_r(&t, &gm) != NULL) {
		res = nmsg_strbuf_append(sb, "%d-%02d-%02d %02d:%02d:%02d",
					 1900 + gm.tm_year,
					 1 + gm.tm_mon,
					 gm.tm_mday,
					 gm.tm_hour,
					 gm.tm_min,
					 gm.tm_sec);
	}

	return (res);
}

static nmsg_res
time_parse(nmsg_message_t m,
	   struct nmsg_msgmod_field *field,
	   const char *value,
	   void **ptr,
	   size_t *len,
	   const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	time_t * t;
	struct tm gm;

	if (!strptime(value, "%Y-%m-%d %T", &gm)) {
		return (nmsg_res_parse_error);
	}

	t = malloc(sizeof(*t));
	*t = timegm(&gm);

	*ptr = t;
	*len = sizeof(*t);

	return (nmsg_res_success);
}

static nmsg_res
dns_name_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	(void)msg; /* unused parameter */
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
dns_name_format(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	ProtobufCBinaryData *rrname = ptr;
	char name[WDNS_PRESLEN_NAME];
	nmsg_res res = nmsg_res_success;

	if (rrname->data != NULL &&
	    rrname->len > 0 &&
	    rrname->len <= WDNS_MAXLEN_NAME)
	{
		wdns_domain_to_str(rrname->data, rrname->len, name);
		res = nmsg_strbuf_append(sb, "%s", name);
	}
	return (res);
}

static nmsg_res
dns_name_parse(nmsg_message_t m,
	       struct nmsg_msgmod_field *field,
	       const char *value,
	       void **ptr,
	       size_t *len,
	       const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	wdns_res res;
	wdns_name_t *name;

	name = malloc(sizeof(*name));
	if (name == NULL) {
		return (nmsg_res_memfail);
	}

	res = wdns_str_to_name_case(value, name);
	if (res != wdns_res_success) {
		free(name);
		return (nmsg_res_parse_error);
	}

	*ptr = name->data;
	*len = name->len;

	free(name);

	return (nmsg_res_success);
}

static nmsg_res
dns_type_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	(void)msg; /* unused parameter */
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
dns_type_format(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	uint16_t rrtype;
	const char *s;
	char buf[sizeof("TYPE65535")];
	nmsg_res res = nmsg_res_success;

	memcpy(&rrtype, ptr, sizeof(rrtype));
	s = wdns_rrtype_to_str(rrtype);
	if (s == NULL) {
		snprintf(buf, sizeof(buf), "TYPE%u", rrtype);
		s = &buf[0];
	}
	res = nmsg_strbuf_append(sb, "%s", s);
	return (res);
}

static nmsg_res
dns_type_parse(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       const char *value,
	       void **ptr,
	       size_t *len,
	       const char *endline)
{
	(void)msg; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	uint16_t *rrtype;

	rrtype = malloc(sizeof(*rrtype));
	if (rrtype == NULL) {
		return (nmsg_res_memfail);
	}

	*rrtype = wdns_str_to_rrtype(value);
	if (*rrtype == 0) {
		free(rrtype);
		return (nmsg_res_parse_error);
	}

	*ptr = rrtype;
	*len = sizeof(*rrtype);

	return (nmsg_res_success);
}

static nmsg_res
dns_class_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	(void)msg; /* unused parameter */
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
dns_class_format(nmsg_message_t m,
		 struct nmsg_msgmod_field *field,
		 void *ptr,
		 struct nmsg_strbuf *sb,
		 const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	uint16_t rrclass;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrclass, ptr, sizeof(rrclass));
	s = wdns_rrclass_to_str(rrclass);
	res = nmsg_strbuf_append(sb, "%s", s ? s : "<UNKNOWN>");
	return (res);
}

static nmsg_res
dns_class_parse(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		const char *value,
		void **ptr,
		size_t *len,
		const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	uint16_t *rrclass;

	rrclass = malloc(sizeof(*rrclass));
	if (rrclass == NULL) {
		return (nmsg_res_memfail);
	}

	*rrclass = wdns_str_to_rrclass(value);
	*rrclass = WDNS_CLASS_IN;
	if (*rrclass == 0) {
		free(rrclass);
		return (nmsg_res_parse_error);
	}

	*ptr = rrclass;
	*len = sizeof(*rrclass);

	return (nmsg_res_success);
}

static nmsg_res
dns_rdata_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	(void)field; /* unused parameter */
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;
	uint32_t *rrtype, *rrclass;
	size_t len;

	res = nmsg_message_get_field(msg, "rrtype", 0, (void**) &rrtype, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(msg, "rrclass", 0, (void**) &rrclass, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	buf = wdns_rdata_to_str(rdata->data, rdata->len, *rrtype, *rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (res);
}

static nmsg_res
dns_rdata_format(nmsg_message_t msg,
		 struct nmsg_msgmod_field *field,
		 void *ptr,
		 struct nmsg_strbuf *sb,
		 const char *endline)
{
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;
	uint32_t *rrtype, *rrclass;
	size_t len;

	res = nmsg_message_get_field(msg, "rrtype", 0, (void**) &rrtype, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(msg, "rrclass", 0, (void**) &rrclass, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	buf = wdns_rdata_to_str(rdata->data, rdata->len, *rrtype, *rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append(sb, "%s", buf);
	free(buf);
	return (res);
}

static nmsg_res
dns_rdata_parse(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		const char *value,
		void **ptr,
		size_t *len,
		const char *endline)
{
	(void)field; /* unused parameter */
	(void)endline; /* unused parameter */
	nmsg_res res;
	wdns_res w_res;
	uint32_t *rrtype, *rrclass;
	size_t f_len;

	res = nmsg_message_get_field(m, "rrtype", 0, (void**) &rrtype, &f_len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (f_len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(m, "rrclass", 0, (void**) &rrclass, &f_len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (f_len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	w_res = wdns_str_to_rdata(value, *rrtype, *rrclass, (uint8_t**)ptr, len);
	if (w_res == wdns_res_parse_error) {
		return (nmsg_res_parse_error);
	} else if (w_res != wdns_res_success) {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dns_message_print(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  void *ptr,
		  struct nmsg_strbuf *sb,
		  const char *endline)
{
	(void)ptr; /* unused parameter */
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

static nmsg_res
dns_message_format(nmsg_message_t msg,
	           struct nmsg_msgmod_field *field,
	           void *ptr,
	           struct nmsg_strbuf *sb,
	           const char *endline)
{
	(void)ptr; /* unused parameter */
	(void)endline; /* unused parameter */
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
				nmsg_strbuf_append(sb, "%s", s);
				free(s);
				wdns_clear_message(&dns);
				return (nmsg_res_success);
			}
			wdns_clear_message(&dns);
		}
	}
	nmsg_strbuf_append(sb, "<PARSE ERROR>");
	return (nmsg_res_success);
}

static nmsg_res
dns_message_parse(nmsg_message_t m,
		  struct nmsg_msgmod_field *field,
		  const char *value,
		  void **ptr,
		  size_t *len,
		  const char *endline)
{
	(void)m; /* unused parameter */
	(void)field; /* unused parameter */
	(void)value; /* unused parameter */
	(void)ptr; /* unused parameter */
	(void)len; /* unused parameter */
	(void)endline; /* unused parameter */
	return (nmsg_res_notimpl);
}
