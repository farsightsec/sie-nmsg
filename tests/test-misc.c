/*
 * Copyright (c) 2018 by Farsight Security, Inc.
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "errors.h"

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"
#include "nmsg/sie/defs.h"

#define NAME	"test-misc"


/* Fill a blank? message object with nonsense. */
static int
fill_message(nmsg_message_t m)
{
	size_t nf, i;

	check_return(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check_return(nf != 0);

	for (i = 0; i < nf; i++) {
		check_return(nmsg_message_set_field_by_idx(m, i, 0, (const uint8_t *)"ABCD", 4) == nmsg_res_success);
	}

	return 0;
}

/*
 * Compare two nmsg message objects for equality.
 *
 * Since this is a leaf function called by other tests,
 * we don't even bother with returning 1 or -1;
 * any non-zero return is simply treated an error.
 */
static int
cmp_nmessages(nmsg_message_t m1, nmsg_message_t m2)
{
	size_t nf1, nf2, i;

	check_return(nmsg_message_get_num_fields(m1, &nf1) == nmsg_res_success);
	check_return(nmsg_message_get_num_fields(m2, &nf2) == nmsg_res_success);

	if (!nf1 && !nf2)
		return 0;

	check_return_silent(nf1 == nf2);

	for (i = 0; i < nf1; i++) {
		nmsg_msgmod_field_type ftype1, ftype2;
		const char *name1, *name2;
		size_t nfv1, nfv2;
		unsigned int flags1, flags2;

		check_return(nmsg_message_get_num_field_values_by_idx(m1, i, &nfv1) == nmsg_res_success);
		check_return(nmsg_message_get_num_field_values_by_idx(m2, i, &nfv2) == nmsg_res_success);

		check_return_silent(nfv1 == nfv2);

		check_return(nmsg_message_get_field_flags_by_idx(m1, i, &flags1) == nmsg_res_success);
		check_return(nmsg_message_get_field_flags_by_idx(m2, i, &flags2) == nmsg_res_success);

		check_return_silent(flags1 ==  flags2);

		check_return(nmsg_message_get_field_type_by_idx(m1, i, &ftype1) == nmsg_res_success);
		check_return(nmsg_message_get_field_type_by_idx(m2, i, &ftype2) == nmsg_res_success);

		check_return_silent(ftype1 == ftype2);

		check_return(nmsg_message_get_field_name(m1, i, &name1) == nmsg_res_success);
		check_return(nmsg_message_get_field_name(m2, i, &name2) == nmsg_res_success);

		check_return_silent(!strcmp(name1, name2));

	}

	return 0;
}

static int
test_container(void)
{
	nmsg_container_t c;
	nmsg_message_t m1, m2, m3, *m_arr1, *m_arr2;
	nmsg_msgmod_t mm;
	uint8_t *tmpbuf1, *tmpbuf2, *payload;
	size_t i, tlen1, tlen2, m_len = 0;
	int failed = 0;

	/* This should fail. */
	c = nmsg_container_init(0);
	check_return(c == NULL);

	/*
	 * This container should initialize properly and then eventually
	 * fail when it fills up because it is too small.
	 */
	c = nmsg_container_init(1024);

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	check_return(mm != NULL);

	m1 = nmsg_message_init(mm);
	check_return(m1 != NULL);

	return_if_error(fill_message(m1));

	for (i = 0; i < 12; i++) {

		if (nmsg_container_add(c, m1) != nmsg_res_success) {
			failed = 1;
			break;
		}

	}

	check(failed != 0);

	nmsg_container_destroy(&c);

	/*
	 * Now onto the main test.
	 * Create a container and verify the messages are added to it
	 * successfully and payloads adjusted accordingly.
	 */
	c = nmsg_container_init(NMSG_WBUFSZ_MAX);
	check_return(c != NULL);

	m2 = nmsg_message_init(mm);
	check_return(m2 != NULL);

	payload = malloc(4);
	check_abort(payload != NULL);
	memcpy(payload, "data", 4);
	m3 = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID, 0, payload, 4, NULL);
	check_return(m3 != NULL);

	check(nmsg_container_get_num_payloads(c) == 0);

	check_return(nmsg_container_add(c, m1) == nmsg_res_success);

	/* Test compression. First add a message with an easily compressable field. */
#define REPEAT_FIELD	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	nmsg_message_set_field_by_idx(m2, 0, 0, (const uint8_t *)REPEAT_FIELD, strlen(REPEAT_FIELD));
	check_return(nmsg_container_add(c, m2) == nmsg_res_success);
	check_return(nmsg_container_get_num_payloads(c) == 2);

	check_return(nmsg_container_add(c, m3) == nmsg_res_success);

	/* First try serialization without zlib compression. */
	check_return(nmsg_container_serialize(c, &tmpbuf1, &tlen1, 1, 0, 1, 123) == nmsg_res_success);

	/* Then do it with compression. */
	check_return(nmsg_container_serialize(c, &tmpbuf2, &tlen2, 1, 1, 1, 123) == nmsg_res_success);

	/* The second result (compressed serialized) should be smaller. */
	check(tlen2 < tlen1);

	/* Try deserializing the uncompressed version. */
	check_return(nmsg_container_deserialize(tmpbuf1, tlen1, &m_arr1, &m_len) == nmsg_res_success);
	check_return(m_len == 3);
	free(tmpbuf1);

	/* Also verify the compressed variant. */
	check_return(nmsg_container_deserialize(tmpbuf2, tlen2, &m_arr2, &m_len) == nmsg_res_success);
	check_return(m_len == 3);
	free(tmpbuf2);

	/* Both deserialized messages should look the same. */
	return_if_error(cmp_nmessages(m1, m_arr1[0]));
	return_if_error(cmp_nmessages(m2, m_arr1[1]));

	return_if_error(cmp_nmessages(m1, m_arr2[0]));
	return_if_error(cmp_nmessages(m2, m_arr2[1]));

	/* Skip over the last nmsg because it should seem corrupt. */
	size_t tnf;
	check(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr1[2], &tnf));
	check(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr2[2], &tnf));

	for (i = 0; i < m_len; i++) {
		nmsg_message_destroy(&m_arr1[i]);
		nmsg_message_destroy(&m_arr2[i]);
	}

	nmsg_message_destroy(&m1);
	check(m1 == NULL);

	nmsg_message_destroy(&m2);
	check(m2 == NULL);

	nmsg_message_destroy(&m3);
	check(m3 == NULL);

	nmsg_container_destroy(&c);
	check(c == NULL);

	l_return_test_status();
}

/* Test msgmod lookups by name and msgtype; also convert pres data to payload. */
static int
test_msgmod(void)
{
	nmsg_msgmod_t mod1, mod2;
	void *clos;
	uint8_t *pbuf = NULL;
	size_t psz;

	/* Sanity checks resolving some basic and fake vendor IDs and message types */
	check(nmsg_msgmod_vname_to_vid("sie") == NMSG_VENDOR_SIE_ID);
	check(nmsg_msgmod_get_max_vid() >= NMSG_VENDOR_SIE_ID);
	check(nmsg_msgmod_get_max_msgtype(NMSG_VENDOR_SIE_ID) == NMSG_VENDOR_SIE_DNSNX_ID);
	check(!strcasecmp("sie", nmsg_msgmod_vid_to_vname(NMSG_VENDOR_SIE_ID)));
	check(!strcasecmp("dnsdedupe", nmsg_msgmod_msgtype_to_mname(NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_DNSDEDUPE_ID)));
	check(nmsg_msgmod_mname_to_msgtype(NMSG_VENDOR_SIE_ID, "qr") == NMSG_VENDOR_SIE_QR_ID);

	mod1 = nmsg_msgmod_lookup(NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_DNSDEDUPE_ID);
	check(mod1 != NULL);

	mod2 = nmsg_msgmod_lookup_byname("sie", "dnsdedupe");
	check(mod2 != NULL);
	check(mod1 == mod2);

	mod2 = nmsg_msgmod_lookup_byname("SIE", "reputation");
	check_return(mod2 != NULL);
	check(mod1 != mod2);

	check_return(nmsg_msgmod_init(mod2, &clos) == nmsg_res_success);

	/* Attempt to convert presentation data to payload. */
	const char *nmsg_pres = //"[108] [2018-02-21 17:43:24.311901092] [2:5 SIE newdomain] [a1ba02cf] [] []\n"
		"domain: workable.com.\n"
		"time_seen: 2018-02-21 17:41:32\n"
		"bailiwick: workable.com.\n"
		"rrname: aspmx-bucketlist-dot-org.workable.com.\n"
		"rrclass: IN (1)\n"
		"rrtype: CNAME (5)\n"
		"rdata: qeoqj.x.incapdns.net.\n";

	check(nmsg_msgmod_pres_to_payload(mod2, clos, nmsg_pres) == nmsg_res_success);
	check(nmsg_msgmod_pres_to_payload_finalize(mod2, clos, &pbuf, &psz) == nmsg_res_success);
	check(pbuf != NULL);
	check(psz == 31);

	check(nmsg_msgmod_fini(mod2, &clos) == nmsg_res_success);
	check(clos == NULL);

	if (pbuf)
		free(pbuf);

	l_return_test_status();
}

int
main(void)
{
	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_msgmod() == 0, "test-misc/ test_msgmod");
	check_explicit2_display_only(test_container() == 0, "test-misc/ test_container");

	g_check_test_status(false);
}
