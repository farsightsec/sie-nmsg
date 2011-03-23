/* SIE reputation nmsg message module */

/*
 * Copyright (c) 2011 by Internet Systems Consortium, Inc. ("ISC")
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
