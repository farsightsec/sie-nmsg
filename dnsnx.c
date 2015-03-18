/* SIE DNS NXDOMAIN nmsg message module */

/*
 * Copyright (c) 2010-2012, 2015 by Farsight Security, Inc.
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
#include "dnsnx.pb-c.h"

/* Data. */

struct nmsg_msgmod_field dnsnx_fields[] = {
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
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "soa_rrname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "response_time_sec",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "response_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_SIE,
	.msgtype	= { NMSG_VENDOR_SIE_DNSNX_ID, NMSG_VENDOR_SIE_DNSNX_NAME },

	.pbdescr	= &nmsg__sie__dns_nx__descriptor,
	.fields		= dnsnx_fields
};
