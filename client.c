// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/minmax/minmax.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>

#include "bipartite_match.h"
#include "proto.h"

static struct {
	bool tls;
	bool tls_rx;
	bool tls_tx;
	bool tls_nopad;
	unsigned int tls_ver;
	int verbose;
	char *src;
	char *dst;
	char *src_svc;
	char *dst_svc;
	unsigned int time_stats;
	unsigned int req_size;
	unsigned int resp_size;
	unsigned int read_size;
	unsigned int write_size;
	unsigned int pin_off;
	unsigned int time;
	unsigned int cpu_min;
	unsigned int cpu_max;
	int cpu_src_wrk;
	int cpu_dst_wrk;
	unsigned int mss;
	unsigned int n_conns;
} opt = {
	.tls_ver = TLS_1_3_VERSION,
	.src = "localhost",
	.dst = "localhost",
	.src_svc = "18323",
	.dst_svc = "18323",
	.req_size = ~0U,
	.time = 5,
	.cpu_min = 0,
	.cpu_max = 255,
	.cpu_src_wrk = -1,
	.cpu_dst_wrk = -1,
	.n_conns = 1,
};

#define dbg(fmt...) while (0) { warnx(fmt); }

static void opt_show_uinthex(char buf[OPT_SHOW_LEN], const unsigned int *ui)
{
	sprintf(buf, "0x%x", *ui);
}

static const struct opt_table opts[] = {
	OPT_WITH_ARG("--src <arg>", opt_set_charp, opt_show_charp,
		     &opt.src, "Source server"),
	OPT_WITH_ARG("--dst <arg>", opt_set_charp, opt_show_charp,
		     &opt.dst, "Destination server"),
	OPT_WITH_ARG("--src-svc <arg>", opt_set_charp, opt_show_charp,
		     &opt.src_svc, "Source server"),
	OPT_WITH_ARG("--dst-svc <arg>", opt_set_charp, opt_show_charp,
		     &opt.dst_svc, "Destination server"),
	OPT_WITH_ARG("--req-size|-s <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.req_size, "Request size"),
	OPT_WITH_ARG("--resp-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.resp_size, "Request size"),
	OPT_WITH_ARG("--read-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.read_size, "Buffer size for write/send syscall"),
	OPT_WITH_ARG("--write-size <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.write_size, "Buffer size for read/recv syscall"),
	OPT_WITH_ARG("--pin-off <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.pin_off, "CPU pin offset"),
	OPT_WITH_ARG("--cpu-min <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.cpu_min, "min CPU number for connection"),
	OPT_WITH_ARG("--cpu-max <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.cpu_max, "max CPU number for connection"),
	OPT_WITH_ARG("--cpu-src-wrk <arg>", opt_set_intval, opt_show_intval,
		     &opt.cpu_src_wrk, "max CPU number for connection"),
	OPT_WITH_ARG("--cpu-dst-wrk <arg>", opt_set_intval, opt_show_intval,
		     &opt.cpu_dst_wrk, "max CPU number for connection"),
	OPT_WITH_ARG("--time|-t <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.time, "Test length"),
	OPT_WITH_ARG("--time-stats|-T <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.time_stats,
		     "Time stats - (0) none, (1) hist, (2) hist+pstats"),
	OPT_WITH_ARG("--mss|-M <arg>", opt_set_uintval, opt_show_uintval,
		     &opt.mss, "MSS for TCP"),
	OPT_WITHOUT_ARG("--tls", opt_set_bool, &opt.tls,
			"Enable TLS in both directions"),
	OPT_WITH_ARG("--tls-ver <arg>", opt_set_uintval, opt_show_uinthex,
		     &opt.tls_ver, "Version of TLS as per kernel defines"),
	OPT_WITHOUT_ARG("--tls-rx", opt_set_bool, &opt.tls_rx,
			"Enable TLS for Rx"),
	OPT_WITHOUT_ARG("--tls-tx", opt_set_bool, &opt.tls_tx,
			"Enable TLS for Tx"),
	OPT_WITHOUT_ARG("--tls-nopad", opt_set_bool, &opt.tls_nopad,
			"Enable TLS no padding optimization for Rx"),
	OPT_WITH_ARG("--num-connections|-n <arg>",
		     opt_set_uintval, opt_show_uintval,
		     &opt.n_conns, "Number of connections"),
	OPT_WITHOUT_ARG("--verbose|-v", opt_inc_intval, &opt.verbose,
			"Verbose mode (can be specified more than once)"),
	OPT_WITHOUT_ARG("--usage|--help|-h", opt_usage_and_exit,
			"kpeft client",	"Show this help message"),
	OPT_ENDTABLE
};

static struct kpm_connect_reply *
spawn_conn(int src, int dst, struct sockaddr_in6 *addr, socklen_t len)
{
	struct kpm_connect_reply **replies;
	struct kpm_connect_reply *conns;
	struct kpm_connect_reply *id;
	struct bim_state *bim;
	struct bim_edge m;
	unsigned int i;
	int *seq;

	if (!opt.n_conns)
		return NULL;
	conns = calloc(opt.n_conns, sizeof(*conns));
	if (!conns)
		return NULL;
	replies = calloc(opt.n_conns, sizeof(*replies));
	if (!replies)
		goto err_free_conns;
	seq = calloc(opt.n_conns, sizeof(int));
	if (!seq)
		goto err_free_replies;
	bim = bim_init();
	if (!bim)
		goto err_free_seq;

again:
	for (i = 0; i < opt.n_conns; i++) {
		seq[i] = kpm_send_connect(src, addr, len, opt.mss);
		if (seq[i] < 0)
			err(7, "Failed to connect");
	}
	for (i = 0; i < opt.n_conns; i++) {
		id = kpm_receive(src);
		if (!id)
			errx(7, "No connection ID");

		if (!kpm_good_reply(id, KPM_MSG_TYPE_CONNECT, seq[i]))
			errx(7, "Invalid connection ID %d %d",
			     id->hdr.type, id->hdr.len);

		replies[i] = id;
	}

	for (i = 0; i < opt.n_conns; i++) {
		bool good, bim_unique;

		id = replies[i];

		good = clamp(id->local.cpu, opt.cpu_min, opt.cpu_max) ==
			id->local.cpu &&
		       clamp(id->remote.cpu, opt.cpu_min, opt.cpu_max) ==
			id->remote.cpu;
		bim_unique = good &&
			bim_add_edge(bim, id->local.cpu, id->remote.cpu, id);

		warnx("Connection established %d:cpu %d | %d:cpu %d - %s",
		      id->local.id, id->local.cpu,
		      id->remote.id, id->remote.cpu,
		      good && bim_unique ? "good" :
		      (good ? "duplicate" : "out of range"));

		if (!bim_unique) {
			bool fail = kpm_req_disconnect(src, id->local.id) < 0 ||
				    kpm_req_disconnect(dst, id->remote.id) < 0;
			free(id);
			if (fail) {
				warnx("Disconnect failed");
				i = opt.n_conns - i - 1;
				goto err_drain;
			}
		}
	}

	if (bim_match_size(bim) < opt.n_conns)
		goto again;

	i = 0;
	bim_for_each_edge(bim, &m) {
		id = m.cookie;

		if (m.is_match && i < opt.n_conns) {
			warnx("Connected %d:cpu %d | %d:cpu %d",
			      id->local.id, id->local.cpu,
			      id->remote.id, id->remote.cpu);
			memcpy(&conns[i], id, sizeof(*id));
			i++;
		} else {
			kpm_req_disconnect(src, id->local.id);
			kpm_req_disconnect(dst, id->remote.id);
		}
		free(id);
	}

	free(seq);
	free(replies);
	return conns;

err_drain:
	bim_for_each_edge(bim, &m) {
		id = m.cookie;
		kpm_req_disconnect(src, id->local.id);
		kpm_req_disconnect(dst, id->remote.id);
		free(id);
	}
	bim_destroy(bim);
err_free_seq:
	free(seq);
err_free_replies:
	free(replies);
err_free_conns:
	free(conns);
	return NULL;
}

static int spawn_worker(int fd, int cpu, __u32 *wid)
{
	struct __kpm_generic_u32 *id;
	struct kpm_empty *ack;
	int seq;

	seq = kpm_send_empty(fd, KPM_MSG_TYPE_SPAWN_PWORKER);
	if (seq < 0) {
		warn("Failed to spawn");
		return 1;
	}

	id = kpm_receive(fd);
	if (!id) {
		warnx("No ack for spawn");
		return 1;
	}

	if (!kpm_good_reply(id, KPM_MSG_TYPE_SPAWN_PWORKER, seq)) {
		warnx("Invalid spawn ack %d %d", id->hdr.type, id->hdr.len);
		free(id);
		return 1;
	}

	*wid = id->val;
	free(id);

	seq = kpm_send_pin_worker(fd, *wid, cpu);
	if (seq < 0) {
		warn("Failed to pin");
		return 1;
	}

	ack = kpm_receive(fd);
	if (!ack) {
		warnx("No ack for pin");
		return 1;
	}

	if (!kpm_good_reply(ack, KPM_MSG_TYPE_PIN_WORKER, seq)) {
		warnx("Invalid ack for pin %d %d", id->hdr.type, id->hdr.len);
		free(ack);
		return 1;
	}
	free(ack);

	return 0;
}

static void
show_cpu_stat(const char *pfx, struct kpm_test_results *result, unsigned int id)
{
	struct kpm_cpu_load *cpu = &result->cpu_load[id];

	if (cpu->id != id) {
		warnx("Sparse CPU IDs %d != %d!", cpu->id, id);
		return;
	}

	warnx("  %sCPU%3d: usr:%5.2f%% sys:%5.2f%% idle:%5.2f%% iow:%5.2f%% irq:%5.2f%% sirq:%5.2f%%",
	      pfx, id, cpu->user / 100.0, cpu->system / 100.0,
	      cpu->idle / 100.0, cpu->iowait / 100.0, cpu->irq / 100.0,
	      cpu->sirq / 100.0);
}

static void
dump_result(struct kpm_test_results *result, const char *dir,
	    struct kpm_connect_reply *conns, bool local)
{
	unsigned int end = 0, i, r;
	int start = -1;

	warnx("== %s", dir);
	for (r = 0; r < opt.n_conns; r++)
		warnx("  Tx%7.3lf Gbps (%llu bytes in %u usec)",
		      (double)result->res[r].tx_bytes * 8 /
		      result->time_usec /
		      1000,
		      result->res[r].tx_bytes,
		      result->time_usec);
	for (r = 0; r < opt.n_conns; r++)
		warnx("  Rx%7.3lf Gbps (%llu bytes in %u usec)",
		      (double)result->res[r].rx_bytes * 8 /
		      result->time_usec /
		      1000,
		      result->res[r].rx_bytes,
		      result->time_usec);
	warnx("  TCP retrans rtt rttvar d_ce snd_wnd cwnd");
	for (r = 0; r < opt.n_conns; r++)
		warnx("      %7u %3u %6u %4u %7u %4u",
		      result->res[r].retrans, result->res[r].rtt,
		      result->res[r].rttvar, result->res[r].delivered_ce,
		      result->res[r].snd_wnd, result->res[r].snd_cwnd);

	for (r = 0; r < opt.n_conns; r++) {
		int flow_cpu;

		flow_cpu = local ? conns[r].local.cpu : conns[r].remote.cpu;
		show_cpu_stat(opt.pin_off ? "net " : "", result, flow_cpu);
		if (opt.pin_off)
			show_cpu_stat("app ", result, flow_cpu + opt.pin_off);
	}

	/* The rest is RR-only */
	if (opt.req_size == ~0U)
		return;

	for (r = 0; r < opt.n_conns; r++)
		warnx("%.1lf RPS",
		      (double)result->res[r].reqs /
		      result->time_usec * 1000000);

	if (opt.time_stats < 1)
		return;

	for (r = 0; r < opt.n_conns; r++) {
		for (i = 0; i < ARRAY_SIZE(result->res[r].lat_hist); i++) {
			if (!result->res[r].lat_hist[i])
				continue;
			if (start < 0)
				start = i;
			end = i + 1;
		}
		for (i = start; i < end; i++) {
			unsigned int val;
			const char *unit;

			if (i < 3) {
				val = 128 << i;
				unit = "ns";
			} else if (i < 13) {
				val = (1ULL << (i + 7)) / 1000;
				unit = "us";
			} else {
				val = (1ULL << (i + 7)) / (1000 * 1000);
				unit = "ms";
			}
			warnx("  [%3d%s] %d",
			      val, unit, result->res[r].lat_hist[i]);
		}
	}

	if (opt.time_stats < 2)
		return;

	for (r = 0; r < opt.n_conns; r++)
		warnx("p25:%uus p50:%uus p90:%uus p99:%uus p999:%uus p9999:%uus",
		      result->res[r].p25 * 128 / 1000,
		      result->res[r].p50 * 128 / 1000,
		      result->res[r].p90 * 128 / 1000,
		      result->res[r].p99 * 128 / 1000,
		      result->res[r].p999 * 128 / 1000,
		      result->res[r].p9999 * 128 / 1000);
}

int main(int argc, char *argv[])
{
	unsigned int src_ncpus, dst_ncpus;
	struct __kpm_generic_u32 *ack_id;
	__u32 *src_wrk_cpu, *dst_wrk_cpu;
	struct kpm_connect_reply *conns;
	struct kpm_test_results *result;
	__u32 *src_wrk_id, *dst_wrk_id;
	struct sockaddr_in6 conn_addr;
	__u32 src_tst_id, dst_tst_id;
	struct addrinfo *addr;
	struct kpm_test *test;
	unsigned int i;
	socklen_t len;
	int src, dst;
	size_t sz;
	int seq;

	opt_register_table(opts, NULL);
	if (!opt_parse(&argc, argv, opt_log_stderr))
		exit(1);

	err_set_progname(argv[0]);

	if (opt.read_size > KPM_MAX_OP_CHUNK ||
	    opt.write_size > KPM_MAX_OP_CHUNK)
		errx(1, "Max read/write size is %d", KPM_MAX_OP_CHUNK);

	src_wrk_id = calloc(opt.n_conns, sizeof(*src_wrk_id));
	dst_wrk_id = calloc(opt.n_conns, sizeof(*dst_wrk_id));
	src_wrk_cpu = calloc(opt.n_conns, sizeof(*src_wrk_cpu));
	dst_wrk_cpu = calloc(opt.n_conns, sizeof(*dst_wrk_cpu));

	addr = net_client_lookup(opt.src, opt.src_svc, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to connect to");

	/* Src */
	src = net_connect(addr);
	freeaddrinfo(addr);
	if (src < 1)
		err(1, "Failed to connect");

	addr = net_client_lookup(opt.dst, opt.dst_svc, AF_UNSPEC, SOCK_STREAM);
	if (!addr)
		errx(1, "Failed to look up service to connect to");

	if (kpm_xchg_hello(src, &src_ncpus))
		errx(2, "Bad hello");

	/* Dst */
	dst = net_connect(addr);
	freeaddrinfo(addr);
	if (dst < 1)
		err(1, "Failed to connect");

	if (kpm_xchg_hello(dst, &dst_ncpus))
		errx(2, "Bad hello");

	/* Main */
	len = sizeof(conn_addr);
	if (kpm_req_tcp_sock(dst, &conn_addr, &len) < 0) {
		warnx("Failed create TCP acceptor");
		goto out;
	}

	conns = spawn_conn(src, dst, &conn_addr, len);
	if (!conns)
		goto out;

	if (opt.tls || opt.tls_rx || opt.tls_tx) {
		struct tls12_crypto_info_aes_gcm_128 aes128 = {};
		unsigned int rx, src_mask, dst_mask;

		aes128.info.version = opt.tls_ver;
		aes128.info.cipher_type = TLS_CIPHER_AES_GCM_128;

		rx = KPM_TLS_RX;
		if (opt.tls_nopad)
			rx |= KPM_TLS_NOPAD;
		if (opt.tls) {
			src_mask = dst_mask = KPM_TLS_TX | rx;
		} else if (opt.tls_rx) {
			src_mask = rx;
			dst_mask = KPM_TLS_TX;
		} else {
			src_mask = KPM_TLS_TX;
			dst_mask = rx;
		}

		for (i = 0; i < opt.n_conns; i++) {
			if (kpm_req_tls(src, conns[i].local.id,
					KPM_TLS_ULP | src_mask,
					&aes128, sizeof(aes128)) ||
			    kpm_req_tls(dst, conns[i].remote.id,
					KPM_TLS_ULP | dst_mask,
					&aes128, sizeof(aes128))) {
				warnx("TLS setup failed");
				goto out_id;
			}
		}
	}

	for (i = 0; i < opt.n_conns; i++) {
		struct kpm_connect_reply *id = &conns[i];

		src_wrk_cpu[i] = opt.cpu_src_wrk;
		if (opt.cpu_src_wrk == -1)
			src_wrk_cpu[i] = id->local.cpu + opt.pin_off;

		dst_wrk_cpu[i] = opt.cpu_dst_wrk;
		if (opt.cpu_dst_wrk == -1)
			dst_wrk_cpu[i] = id->remote.cpu + opt.pin_off;

		if (spawn_worker(src, src_wrk_cpu[i], &src_wrk_id[i]) ||
		    spawn_worker(dst, dst_wrk_cpu[i], &dst_wrk_id[i]))
			goto out_id;
	}

	sz = sizeof(*test) + opt.n_conns * sizeof(test->specs[0]);
	test = malloc(sz);
	memset(test, 0, sz);

	test->n_conns = opt.n_conns;
	test->time_sec = opt.time;
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = conns[i].remote.id;
		test->specs[i].worker_id = dst_wrk_id[i];
		test->specs[i].read_size = opt.read_size;
		test->specs[i].write_size = opt.write_size;
		if (opt.req_size == ~0U) {
			test->specs[i].type = KPM_TEST_TYPE_STREAM;
		} else {
			test->specs[i].type = KPM_TEST_TYPE_RR;
			test->specs[i].arg.rr.req_size = opt.req_size;
			test->specs[i].arg.rr.resp_size = opt.resp_size ?: opt.req_size;
			test->specs[i].arg.rr.timings = opt.time_stats;
		}
	}

	seq = kpm_send(dst, &test->hdr, sz, KPM_MSG_TYPE_TEST);

	ack_id = kpm_receive(dst);
	if (!kpm_good_reply(ack_id, KPM_MSG_TYPE_TEST, seq)) {
		warnx("Invalid ack for test %d %d",
		      ack_id->hdr.type, ack_id->hdr.len);
		goto out_id;
	}
	dst_tst_id = ack_id->val;
	dbg("Test id dst %d", dst_tst_id);
	free(ack_id);

	test->active = 1;
	for (i = 0; i < opt.n_conns; i++) {
		test->specs[i].connection_id = conns[i].local.id;
		test->specs[i].worker_id = src_wrk_id[i];
	}

	seq = kpm_send(src, &test->hdr, sz, KPM_MSG_TYPE_TEST);
	free(test);

	ack_id = kpm_receive(src);
	if (!kpm_good_reply(ack_id, KPM_MSG_TYPE_TEST, seq)) {
		warnx("Invalid ack for test %d %d",
		      ack_id->hdr.type, ack_id->hdr.len);
		goto out_id;
	}
	src_tst_id = ack_id->val;
	dbg("Test id src %d", src_tst_id);
	free(ack_id);

	/* Source worker is done */
	result = kpm_receive(src);
	if (!result) {
		warnx("No result");
		goto out_id;
	}
	sz = sizeof(*result) + opt.n_conns * sizeof(result->res[0]);
	if (result->hdr.type != KPM_MSG_TYPE_TEST_RESULT ||
	    result->hdr.len < sz)
		warnx("Invalid result %d %d",
		      result->hdr.type, result->hdr.len);
	else
		dump_result(result, "Source", conns, true);
	free(result);

	/* Stop the test on both ends */
	if (kpm_req_end_test(src, src_tst_id) ||
	    kpm_req_end_test(dst, dst_tst_id))
		warnx("Failed to stop test");

	/* Destination worker is done */
	result = kpm_receive(dst);
	if (!result) {
		warnx("No result");
		goto out_id;
	}
	if (result->hdr.type != KPM_MSG_TYPE_TEST_RESULT ||
	    result->hdr.len < sizeof(*result) + sizeof(result->res[0]))
		warnx("Invalid result %d %d",
		      result->hdr.type, result->hdr.len);
	else
		dump_result(result, "Target", conns, false);
	free(result);

out_id:
	free(conns);
out:
	close(src);
	close(dst);

	return 0;
}
