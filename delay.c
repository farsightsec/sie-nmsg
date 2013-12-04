/* SIE delay nmsg message module */

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

/* Import. */

#include "defs.h"
#include "delay.pb-c.h"

/* Data. */

struct nmsg_msgmod_field delay_fields[] = {
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "query_ip"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip"
	},
	{
		.type = nmsg_msgmod_ft_double,
		.name = "delay"
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "response_time_sec"
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_SIE,
	.msgtype	= { NMSG_VENDOR_SIE_DELAY_ID, NMSG_VENDOR_SIE_DELAY_NAME },

	.pbdescr	= &nmsg__sie__delay__descriptor,
	.fields		= delay_fields 
};
