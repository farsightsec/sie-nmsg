/* SIE DNS Negative QR nmsg message module */

/*
 * Copyright (c) 2010-2012 by Farsight Security, Inc.
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

#include <wdns.h>

#include "defs.h"
#include "dnsnegqr.pb-c.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(dnsnegqr_rcode_print);

/* Data. */

struct nmsg_msgmod_field dnsnegqr_fields[] = {
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "qname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qclass",
		.print = dns_class_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qtype",
		.print = dns_type_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rcode",
		.print = dnsnegqr_rcode_print
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
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_SIE,
	.msgtype	= { NMSG_VENDOR_SIE_DNSNEGQR_ID, NMSG_VENDOR_SIE_DNSNEGQR_NAME },

	.pbdescr	= &nmsg__sie__dns_neg_qr__descriptor,
	.fields		= dnsnegqr_fields
};

/* Private. */

static nmsg_res
dnsnegqr_rcode_print(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  void *ptr,
		  struct nmsg_strbuf *sb,
		  const char *endline)
{
	const char *s;
	uint16_t *rcode = ptr;

	s = wdns_rcode_to_str(*rcode);
	return (nmsg_strbuf_append(sb, "%s: %s (%hu)%s",
				   field->name,
				   s ? s : "<UNKNOWN>",
				   *rcode, endline));
}

