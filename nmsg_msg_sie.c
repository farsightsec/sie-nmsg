/* nmsg_msg_sie.c - SIE nmsg_msg modules */

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

#include <stdlib.h>

#include <nmsg.h>
#include <nmsg/msgmod_plugin.h>

#include <wdns.h>

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dnsdedupe
#include "dnsdedupe.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_qr
#include "qr.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_reputation
#include "reputation.c"
#undef nmsg_msgmod_ctx

/* Export. */

struct nmsg_msgmod_plugin *nmsg_msgmod_ctx_array[] = {
	&nmsg_msgmod_ctx_dnsdedupe,
	&nmsg_msgmod_ctx_qr,
	&nmsg_msgmod_ctx_reputation,
	NULL
};
