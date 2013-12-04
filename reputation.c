/* SIE reputation nmsg message module */

/*
 * Copyright (c) 2011 by Farsight Security, Inc.
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

#include "reputation.pb-c.c"

struct nmsg_msgmod_field reputation_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "tag"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "value"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "address"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "netmask"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "host"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "domain"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "nameserver"
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "uri"
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "port"
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_SIE,
	.msgtype	= { NMSG_VENDOR_SIE_REPUTATION_ID, NMSG_VENDOR_SIE_REPUTATION_NAME },
	.pbdescr	= &nmsg__sie__reputation__descriptor,
	.fields		= reputation_fields
};
