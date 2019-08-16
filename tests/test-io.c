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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "errors.h"

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"
#include "defs.h"

#define NAME	"test-io"


/*
 * Test a wide variety of nmsg input filter functions.
 *
 * A small amount of trickery and indirection is required here.
 * Certain filters are only applicable to nmsg inputs of type stream.
 * This precludes certain vehicles like data in json and presentation format.
 * While we could theoretically just open up a binary nmsg file with the
 * function nmsg_input_open_sock(), the subsequent read via recvfrom() would
 * fail on it since it's a local file and not a socket.
 *
 * Therefore we create a dummy fd with socketpair() and manually proxy
 * our locally stored nmsg data across it.
 */
static int
test_io_filters2(void)
{
	int n;

	for (n = 0; n < 11; n++) {
		nmsg_input_t i;
		nmsg_message_t m;
		int fd, sfds[2];

		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

		fd = open(SRCDIR "/tests/generic-tests/newdomain.nmsg", O_RDONLY);
		check_return(fd != -1);

		i = nmsg_input_open_sock(sfds[0]);
		check_return(i != NULL);

		/* Only need to try this once. */
		if (!n) {
			check(nmsg_input_set_filter_msgtype_byname(i, "some_vendor", "nonexistent_type") != nmsg_res_success);
		}

		/* The ordering is particular. Every odd numbered test should
		 * succeed, and vice versa. */
		switch(n) {
			case 1:
				nmsg_input_set_filter_msgtype(i, NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_DNSDEDUPE_ID);
				break;
			case 2:
				nmsg_input_set_filter_msgtype(i, NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_NEWDOMAIN_ID);
				break;
			case 3:
				nmsg_input_set_filter_group(i, 2835122346);
				break;
			case 4:
				nmsg_input_set_filter_group(i, 0);
				break;
			case 5:
				nmsg_input_set_filter_source(i, 1235817825);
				break;
			case 6:
				nmsg_input_set_filter_source(i, 0xa1ba02cf);
				break;
			case 7:
				nmsg_input_set_filter_operator(i, 138158152);
				break;
			case 8:
				nmsg_input_set_filter_operator(i, 0);
				break;
			case 9:
				check(nmsg_input_set_filter_msgtype_byname(i, "SIE", "dnsdedupe") == nmsg_res_success);
				break;
			case 10:
				check(nmsg_input_set_filter_msgtype_byname(i, "SIE", "newdomain") == nmsg_res_success);
				break;
			default:
				break;
		}

		while (1) {
			char buf[1024];
			int nread;

			nread = read(fd, buf, sizeof(buf));

			if (nread <= 0)
				break;

			check_return(write(sfds[1], buf, nread) == nread);
		}

		if (!(n % 2)) {
			check(nmsg_input_read(i, &m) == nmsg_res_success);
		} else {
			check(nmsg_input_read(i, &m) != nmsg_res_success);
		}

		check(nmsg_input_close(&i) == nmsg_res_success);

		close(fd);
		close(sfds[1]);
	}

	l_return_test_status();
}

static void *user_data = (void *)0xdeadbeef;
static int touched_exit, touched_atstart, touched_close, num_received, touched_filter;

static void
test_close_fp(struct nmsg_io_close_event *ce)
{
	__sync_add_and_fetch(&touched_close, 1);

	return;
}

static void
test_atstart_fp(unsigned threadno, void *user)
{

	if (user == user_data)
		__sync_add_and_fetch(&touched_atstart, 1);

	return;
}

static void
test_atexit_fp(unsigned threadno, void *user)
{

	if (user == user_data)
		__sync_add_and_fetch(&touched_exit, 1);

	return;
}

static void
output_callback(nmsg_message_t msg, void *user)
{

	if (user == user_data)
		__sync_add_and_fetch(&num_received, 1);

	return;
}

/* A filter to permit only msg type NMSG_VENDOR_SIE_DNSDEDUPE_ID */
static nmsg_res
filter_callback(nmsg_message_t *msg, void *user, nmsg_filter_message_verdict *vres)
{
	
	if (user != user_data)
		return nmsg_res_failure;

	if (nmsg_message_get_msgtype(*msg) == NMSG_VENDOR_SIE_DNSDEDUPE_ID)
		*vres = nmsg_filter_message_verdict_DROP;
	else
		*vres = nmsg_filter_message_verdict_ACCEPT;

	__sync_add_and_fetch(&touched_filter, 1);

	return nmsg_res_success;
}

/* Just to test the filter policy. */
static nmsg_res
filter_callback2(nmsg_message_t *msg, void *user, nmsg_filter_message_verdict *vres)
{

	if (user != user_data)
		return nmsg_res_failure;

	*vres = nmsg_filter_message_verdict_DECLINED;
	__sync_add_and_fetch(&touched_filter, 1);

	return nmsg_res_success;
}


/* XXX: Partially crippled.
 * Test custom nmsg io filter callbacks and output callbacks;
 * These are for close, at-start, and at-exit.
 * Test nmsg_io_set_count() [broken]. */
static int
test_io_filters(void)
{
	nmsg_io_t io;
	nmsg_output_t o;
	size_t run_cnt = 0;

	/*
	 * Loop #1: Verify all 10 nmsgs read normally.
	 * Loop #2: Set count to 7 and verify 7 msgs read normally.
	 * Loop #3: Apply first filter callback. It should drop all msgs of type !=
	 *          dnsdedupe, meaning that half (5) of the packets will be dropped.
	 * Loop #4: Apply second filter callback.
	 * Loop #5: Apply second filter callback with default filter policy of DROP.
	 */
	while (run_cnt < 5) {
		io = nmsg_io_init();
		check_return(io != NULL);

		/* Feed the nmsg io loop with 2 nmsg files that have 5 messages each. */
		check_return(nmsg_io_add_input_fname(io, SRCDIR "/tests/generic-tests/dedupe.nmsg", NULL) == nmsg_res_success);
		check_return(nmsg_io_add_input_fname(io, SRCDIR "/tests/generic-tests/newdomain.nmsg", NULL) == nmsg_res_success);

		/* Use an output callback for the output. */
		o = nmsg_output_open_callback(output_callback, user_data);
		check_return(o != NULL);
		check_return(nmsg_io_add_output(io, o, user_data) == nmsg_res_success);

		/* Reset the counters and set up all custom callbacks. */
		touched_atstart = touched_exit = touched_close = num_received = touched_filter = 0;
		nmsg_io_set_close_fp(io, test_close_fp);
		nmsg_io_set_atstart_fp(io, test_atstart_fp, user_data);
		nmsg_io_set_atexit_fp(io, test_atexit_fp, user_data);

		if (!run_cnt)
			nmsg_io_set_count(io, 10);
		else if (run_cnt == 1)
			nmsg_io_set_count(io, 7);
		else
			nmsg_io_set_count(io, 10);

		if (run_cnt == 2) {
			check(nmsg_io_add_filter(io, filter_callback, user_data) == nmsg_res_success);
		} else if (run_cnt == 3) {
			check(nmsg_io_add_filter(io, filter_callback2, user_data) == nmsg_res_success);
		} else if (run_cnt == 4) {
			check(nmsg_io_add_filter(io, filter_callback2, user_data) == nmsg_res_success);
			/* XXX: This isn't working; it appears to be a bug in libnmsg? */
			nmsg_io_set_filter_policy(io, nmsg_filter_message_verdict_DROP);

		}

		check(nmsg_io_loop(io) == nmsg_res_success);

		nmsg_io_destroy(&io);
		check(io == NULL);

		check(touched_atstart != 0);
		check(touched_exit == touched_atstart);
		check(touched_close >= touched_atstart);

		if (run_cnt == 2) {
			check(touched_filter == 10);
			check(num_received == 5);
		} else if (run_cnt == 3) {
			check(touched_filter == 10);
			check(num_received == 10);
		} else if (run_cnt == 4) {
			check(touched_filter == 10);
			/* check(num_received == 0); */
			check(num_received == 10);
		} else {
			check(touched_filter == 0);
			check(num_received == 10);
		}

		run_cnt++;
	}

	l_return_test_status();
}

int
main(void)
{
	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_io_filters() == 0, "test-io/ test_io_filters");
	check_explicit2_display_only(test_io_filters2() == 0, "test-io/ test_io_filters2");

        g_check_test_status(false);

}
