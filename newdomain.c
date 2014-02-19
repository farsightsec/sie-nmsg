/* SIE DNS new domain message module */

/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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
#include "newdomain.pb-c.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(nd_dns_rdata_print);

/* Data. */

struct nmsg_msgmod_field newdomain_fields[] = {
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "domain",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "time_seen",
		.print = time_print
	},
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
		.print = nd_dns_rdata_print
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
	.msgtype	= { NMSG_VENDOR_SIE_NEWDOMAIN_ID, NMSG_VENDOR_SIE_NEWDOMAIN_NAME },

	.pbdescr	= &nmsg__sie__new_domain__descriptor,
	.fields		= newdomain_fields 
};

static nmsg_res
nd_dns_rdata_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field __attribute__((unused)),
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	Nmsg__Sie__NewDomain *dns = (Nmsg__Sie__NewDomain *) nmsg_message_get_payload(msg);
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;

	if (dns == NULL)
		return (nmsg_res_failure);

	if (dns->has_rrtype == false || dns->has_rrclass == false)
		return (nmsg_res_failure);

	buf = wdns_rdata_to_str(rdata->data, rdata->len, dns->rrtype, dns->rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (res);
}

