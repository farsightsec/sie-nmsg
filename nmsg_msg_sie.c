/* nmsg_msg_sie.c - SIE nmsg_msg modules */

/*
 * Copyright (c) 2010-2011 by Farsight Security, Inc.
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

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_delay
#include "delay.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_newdomain
#include "newdomain.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dnsnegqr
#include "dnsnegqr.c"
#undef nmsg_msgmod_ctx

/* Export. */

struct nmsg_msgmod_plugin *nmsg_msgmod_ctx_array[] = {
	&nmsg_msgmod_ctx_dnsdedupe,
	&nmsg_msgmod_ctx_qr,
	&nmsg_msgmod_ctx_reputation,
	&nmsg_msgmod_ctx_delay,
	&nmsg_msgmod_ctx_newdomain,
	&nmsg_msgmod_ctx_dnsnegqr,
	NULL
};
