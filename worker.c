// SPDX-License-Identifier: BSD-3-Clause
/* Copyright Meta Platforms, Inc. and affiliates */

#define _GNU_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/errqueue.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <liburing.h>

#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/minmax/minmax.h>
#include <ccan/time/time.h>

#include "cpu_stat.h"
#include "tcp.h"
#include "proto.h"
#include "proto_dbg.h"
#include "server.h"
#include "tcp.h"

struct connection;
struct iou_zcrx {
	struct io_uring *ring;
	void *area_base;
	void *ring_ptr;
	size_t area_size;
	size_t ring_size;
	struct io_uring_zcrx_rq rq_ring;
	unsigned int ifindex;
};

#define IOU_PENDING_SENDS	16

/* Main worker state AKA self */
struct worker_state {
	int main_sock;
	int epollfd;
	unsigned int id;
	int quit;
	struct kpm_test *test;
	struct cpu_stat *cpu_start;
	struct timemono test_start;
	struct timemono prev_loop;
	unsigned int test_len_msec;
	bool memcmp;

	struct iou_opts iou_opts;
	struct io_uring ring;
	struct iou_zcrx iou_zcrx;

	int iou_sends;

	int (*prep)(struct worker_state *);
	void (*wait)(struct worker_state *);
	void (*add_test)(struct worker_state *, struct connection *);
	void (*stop_test)(struct worker_state *, struct connection *);

	struct list_head connections;
};

struct connection {
	unsigned int id;
	int fd;
	unsigned int read_size;
	unsigned int write_size;
	__u64 to_send;
	__u64 to_send_comp;
	__u64 to_recv;
	__u64 tot_sent;
	__u64 tot_recv;
	struct kpm_test_spec *spec;
	struct tcp_info init_info;
	union {
		struct {
			unsigned int reqs;
			unsigned int hist[33];
			unsigned int log_len;
			unsigned int log_len_max;
			unsigned int *log;
		} rr;
	};
	unsigned char *buf;
	struct list_node connections;
};

struct kpm_state {
	unsigned char buf[4096];
	size_t len;
};

#define PATTERN_PERIOD 255
#define PATBUF_SZ	(KPM_MAX_OP_CHUNK + PATTERN_PERIOD + 1)
static unsigned char *patbuf;

static struct connection *
worker_find_connection_by_fd(struct worker_state *self, int fd)
{
	struct connection *conn;

	list_for_each(&self->connections, conn, connections) {
		if (conn->fd == fd)
			return conn;
	}
	return NULL;
}

static void
worker_kill_conn(struct worker_state *self, struct connection *conn)
{
	self->stop_test(self, conn);
	close(conn->fd);
	list_del(&conn->connections);
	free(conn->rr.log);
	free(conn);
}

static int
worker_pstat_cmp(unsigned int const *a, unsigned int const *b, void *unused)
{
	return (long long int)*a - (long long int)*b;
}

static void
worker_report_pstats(struct worker_state *self, struct connection *conn,
		     struct kpm_test_result *data)
{
	if (conn->spec->arg.rr.timings < 2)
		return;

        asort(conn->rr.log, conn->rr.log_len, worker_pstat_cmp, NULL);
	data->p25 = conn->rr.log[conn->rr.log_len / 4];
	data->p50 = conn->rr.log[conn->rr.log_len / 2];
	data->p90 = conn->rr.log[(__u64)conn->rr.log_len * 90 / 100];
	data->p99 = conn->rr.log[(__u64)conn->rr.log_len * 99 / 100];
	data->p999 = conn->rr.log[(__u64)conn->rr.log_len * 999 / 1000];
	data->p9999 = conn->rr.log[(__u64)conn->rr.log_len * 9999 / 10000];
}

static void *
tag(void *ptr, int x)
{
	size_t uptr;

	memcpy(&uptr, &ptr, sizeof(size_t));
	return (void *)(uptr | x);
}

static void *
untag(size_t ptr) 
{
	return (void *)(ptr & ~((size_t)0x0f));
}

static int
get_tag(uint64_t ptr)
{
	return (int)(ptr & 0x0f);
}

/* == Worker command handling == */

static void worker_report_test(struct worker_state *self)
{
	struct cpu_stat *cpu, *cpu_pct;
	struct kpm_test_results *res;
	struct connection *conn;
	unsigned int ncpus, i;
	struct timerel t;
	size_t sz;

	kpm_dbg("Reporting results");

	sz = sizeof(*res) + sizeof(res->res[0]) * self->test->n_conns;
	res = malloc(sz);
	memset(res, 0, sz);

	t = timemono_since(self->test_start);
	res->time_usec = time_to_usec(t);
	res->n_conns = self->test->n_conns;
	res->test_id = self->test->test_id;

	ncpus = get_nprocs();
	cpu = cpu_stat_snapshot(ncpus);
	cpu_stat_sub(cpu, self->cpu_start, ncpus);
	cpu_pct = cpu_stat_to_pct00(cpu, ncpus);
	free(cpu);
	for (i = 0; i < ncpus; i++) {
		res->cpu_load[i].id	 = cpu_pct[i].cpu_id;
		res->cpu_load[i].user	 = cpu_pct[i].user;
		res->cpu_load[i].system	 = cpu_pct[i].system;
		res->cpu_load[i].idle	 = cpu_pct[i].idle;
		res->cpu_load[i].iowait	 = cpu_pct[i].iowait;
		res->cpu_load[i].irq	 = cpu_pct[i].irq;
		res->cpu_load[i].sirq	 = cpu_pct[i].sirq;
	}
	free(cpu_pct);

	i = 0;
	list_for_each(&self->connections, conn, connections) {
		struct kpm_test_result *data;
		struct tcp_info info;
		socklen_t info_len;

		do {
			if (i == res->n_conns) {
				warnx("Missing connections!");
				goto skip_results;
			}
			data = &res->res[i];
			data->worker_id = self->id;
			data->connection_id = self->test->specs[i].connection_id;
			i++;
			/* Expect the connections to be in order */
		} while (conn->id != data->connection_id);

		data->type = conn->spec->type;

		info_len = sizeof(conn->init_info);
		if (getsockopt(conn->fd, IPPROTO_TCP, TCP_INFO,
			       (void *)&info, &info_len) < 0) {
			warn("Can't get TCP info");
			goto skip_results;
		}

		data->rx_bytes = conn->tot_recv;
		data->tx_bytes = conn->tot_sent;

		if (conn->spec->type == KPM_TEST_TYPE_RR)
			data->reqs = conn->rr.reqs;

		data->retrans	= info.tcpi_total_retrans -
			conn->init_info.tcpi_total_retrans;
		data->reord_seen = info.tcpi_reord_seen -
			conn->init_info.tcpi_reord_seen;
		data->rtt	= info.tcpi_rtt;
		data->rttvar	= info.tcpi_rttvar;
		data->delivered_ce = info.tcpi_delivered_ce -
			conn->init_info.tcpi_delivered_ce;
		data->snd_wnd	= info.tcpi_snd_wnd;
		data->snd_cwnd	= info.tcpi_snd_cwnd;

		if (verbose > 2)
			print_tcp_info(&info);

		memcpy(data->lat_hist, conn->rr.hist, sizeof(data->lat_hist));
		worker_report_pstats(self, conn, data);

		/* Shut down sending to let the connection drain */
		conn->to_send = 0;
	}
skip_results:

	free(self->test);
	self->test = NULL;

	kpm_send(self->main_sock, &res->hdr, sz, KPM_MSG_WORKER_TEST_RESULT);
	free(res);
}

#define KPM_HNDL(type, name)						\
	{ KPM_MSG_WORKER_ ## type,					\
	  worker_msg_ ## name,						\
	  sizeof(struct kpm_##name),					\
	  stringify(name) }

#define KPM_HNDL_GEN(type, name, gtype)					\
	{ KPM_MSG_WORKER_ ## type,					\
	  worker_msg_ ## name,						\
	  sizeof(struct __kpm_generic_##gtype),				\
	  stringify(name) }

static void
worker_msg_id(struct worker_state *self, struct kpm_header *hdr)
{
	struct __kpm_generic_u32 *id = (void *)hdr;

	self->id = id->val;
}

static void
worker_msg_test(struct worker_state *self, struct kpm_header *hdr)
{
	struct kpm_test *req = (void *)hdr;
	unsigned int i;

	if (self->test) {
		warn("Already running a test");
		self->quit = 1;
		return;
	}

	kpm_dbg("start test %s", req->active ? "act" : "psv");

	self->test = malloc(hdr->len);
	memcpy(self->test, req, hdr->len);

	for (i = 0; i < req->n_conns; i++) {
		struct connection *conn;
		socklen_t info_len;
		__u64 len;
		struct sockaddr_in6 addr;
		socklen_t sock_len = sizeof(addr);

		conn = malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->spec = &self->test->specs[i];
		conn->id = req->specs[i].connection_id;
		// NOTE: this connection was already opened from remote server
		conn->fd = fdpass_recv(self->main_sock);
		getsockname(conn->fd, (struct sockaddr *)&addr, &sock_len);
		printf("----- conn->fd port: %d\n", ntohs(addr.sin6_port));

		info_len = sizeof(conn->init_info);
		if (getsockopt(conn->fd, IPPROTO_TCP, TCP_INFO,
			       (void *)&conn->init_info, &info_len) < 0) {
			warn("Can't get TCP info");
			self->quit = 1;
		}

		if (conn->spec->arg.rr.timings > 1) {
			/* Assume we can't do a round trip < 1us on avg */
			conn->rr.log_len_max =
				self->test->time_sec * 1000 * 1000;
			conn->rr.log = calloc(conn->rr.log_len_max,
					      sizeof(conn->rr.log[0]));
		}

		list_add(&self->connections, &conn->connections);

		conn->read_size = conn->spec->read_size;
		conn->write_size = conn->spec->write_size;

		if (!conn->read_size || conn->read_size > KPM_MAX_OP_CHUNK ||
		    !conn->write_size || conn->write_size > KPM_MAX_OP_CHUNK) {
			warnx("wrong size io op read:%u write:%u",
			      conn->read_size, conn->write_size);
			self->quit = 1;
			return;
		}

		switch (conn->spec->type) {
		case KPM_TEST_TYPE_STREAM:
			len = ~0ULL;
			break;
		case KPM_TEST_TYPE_RR:
			len = conn->spec->arg.rr.req_size;
			break;
		default:
			warnx("Unknown test type");
			return;
		}

		if (req->active)
			conn->to_send = len;
		else
			conn->to_recv = len;

		self->add_test(self, conn);
	}

	self->cpu_start = cpu_stat_snapshot(0);
	self->test_start = time_mono();
	memset(&self->prev_loop, 0, sizeof(self->prev_loop));
	if (self->test->active)
		self->test_len_msec = req->time_sec * 1000;
}

static void
worker_msg_end_test(struct worker_state *self, struct kpm_header *hdr)
{
	struct connection *conn, *next;

	if (self->test)
		worker_report_test(self);

	free(self->cpu_start);
	self->cpu_start = NULL;
	list_for_each_safe(&self->connections, conn, next, connections)
		worker_kill_conn(self, conn);
}

static const struct {
	enum kpm_msg_type type;
	void (*cb)(struct worker_state *self, struct kpm_header *hdr);
	size_t req_size;
	const char *name;
} msg_handlers[] = {
	KPM_HNDL_GEN(ID, id, u32),
	KPM_HNDL(TEST, test),
	KPM_HNDL(END_TEST, end_test),
};

static void worker_handle_main_sock(struct worker_state *self)
{
	struct kpm_header *hdr;
	int i;

	hdr = kpm_receive(self->main_sock);
	if (!hdr) {
		__kpm_dbg("<<", "ctrl recv failed");
		self->quit = 1;
		return;
	}
	kpm_cmd_dbg_start(hdr);

	for (i = 0; i < (int)ARRAY_SIZE(msg_handlers); i++) {
		if (msg_handlers[i].type != hdr->type)
			continue;

		if (hdr->len < msg_handlers[i].req_size) {
			warn("Invalid request for %s", msg_handlers[i].name);
			self->quit = 1;
			break;
		}

		msg_handlers[i].cb(self, hdr);
		break;
	}
	if (i == (int)ARRAY_SIZE(msg_handlers)) {
		warnx("Unknown message type: %d", hdr->type);
		self->quit = 1;
	}

	kpm_cmd_dbg_end(hdr);
	free(hdr);
}

/* == Worker I/O handling == */

static void
worker_record_rr_time(struct worker_state *self, struct connection *conn)
{
	struct timerel delta;
	unsigned int nsec128;
	struct timemono now;
	int hist_idx;

	if (!conn->spec->arg.rr.timings)
		return;

	now = time_mono();
	if (!self->prev_loop.ts.tv_sec)
		goto out_update;

	delta = timemono_between(now, self->prev_loop);
	nsec128 = delta.ts.tv_nsec / 128;
	if (delta.ts.tv_sec)
		nsec128 = ~0U;

	if (conn->spec->arg.rr.timings > 1 &&
	    conn->rr.log_len < conn->rr.log_len_max)
		conn->rr.log[conn->rr.log_len++] = nsec128;

	hist_idx = 0;
	while (nsec128) {
		nsec128 >>= 1;
		hist_idx++;
	}
	conn->rr.hist[hist_idx]++;

out_update:
	self->prev_loop = now;
}

static void
worker_send_arm(struct worker_state *self, struct connection *conn,
		unsigned int events)
{
	struct epoll_event ev = {};

	if (events & EPOLLOUT)
		return;

	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void
worker_send_disarm(struct worker_state *self, struct connection *conn,
		   unsigned int events)
{
	struct epoll_event ev = {};

	if (!(events & EPOLLOUT))
		return;

	ev.events = EPOLLIN;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void
worker_send_finished(struct worker_state *self, struct connection *conn,
		     unsigned int events)
{
	worker_send_disarm(self, conn, events);
	worker_record_rr_time(self, conn);

	if (conn->spec->type != KPM_TEST_TYPE_RR)
		warnx("Done sending for non-RR test");
	else
		conn->rr.reqs++;

	if (self->test->active)
		conn->to_recv =	conn->spec->arg.rr.resp_size;
	else
		conn->to_recv =	conn->spec->arg.rr.req_size;
}

static void
worker_recv_finished(struct worker_state *self, struct connection *conn)
{
	if (!self->test)
		return;

	if (conn->spec->type != KPM_TEST_TYPE_RR)
		warnx("Done sending for non-RR test");

	if (self->test->active)
		conn->to_send =	conn->spec->arg.rr.req_size;
	else
		conn->to_send =	conn->spec->arg.rr.resp_size;
}

static void
worker_handle_completions(struct worker_state *self, struct connection *conn,
			  unsigned int events)
{
	struct sock_extended_err *serr;
	struct msghdr msg = {};
	char control[64] = {};
	struct cmsghdr *cm;
	int ret, n;

	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(conn->fd, &msg, MSG_ERRQUEUE);
	if (ret < 0) {
		if (errno == EAGAIN)
			return;
		warn("failed to clean completions");
		goto kill_conn;
	}

	if (msg.msg_flags & MSG_CTRUNC) {
		warnx("failed to clean completions: truncated cmsg");
		goto kill_conn;
	}

	cm = CMSG_FIRSTHDR(&msg);
	if (!cm) {
		warnx("failed to clean completions: no cmsg");
		goto kill_conn;
	}

	if (cm->cmsg_level != SOL_IP && cm->cmsg_level != SOL_IPV6) {
		warnx("failed to clean completions: wrong level %d",
		      cm->cmsg_level);
		goto kill_conn;
	}

	if (cm->cmsg_type != IP_RECVERR && cm->cmsg_type != IPV6_RECVERR) {
		warnx("failed to clean completions: wrong type %d",
		      cm->cmsg_type);
		goto kill_conn;
	}

	serr = (void *)CMSG_DATA(cm);
	if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
		warnx("failed to clean completions: wrong origin %d",
		      serr->ee_origin);
		goto kill_conn;
	}
	if (serr->ee_errno) {
		warnx("failed to clean completions: error %d",
		      serr->ee_errno);
		goto kill_conn;
	}
	n = serr->ee_data - serr->ee_info + 1;
	conn->to_send_comp -= n;
	kpm_dbg("send complete (%d..%d) %d\n",
		serr->ee_data, serr->ee_info + 1, conn->to_send_comp);

	return;

kill_conn:
	worker_kill_conn(self, conn);
}

static void __worker_iou_send(struct worker_state *self, struct connection *conn)
{
	struct io_uring_sqe *sqe;
	void *src = &patbuf[conn->tot_sent % PATTERN_PERIOD];
	size_t chunk;

	chunk = min_t(size_t, conn->write_size, conn->to_send);
	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_send(sqe, conn->fd, src, chunk, MSG_WAITALL);
	io_uring_sqe_set_data(sqe, tag(conn, KPM_IOU_REQ_TYPE_SEND));
}

static void worker_iou_send_zc(struct worker_state *self, struct connection *conn)
{
	struct io_uring_sqe *sqe;
	void *src = patbuf;
	size_t chunk;

	chunk = min_t(size_t, conn->write_size, conn->to_send);
	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_send_zc_fixed(sqe, conn->fd, src, chunk, MSG_WAITALL, 0, IORING_RECVSEND_FIXED_BUF);
	io_uring_sqe_set_data(sqe, tag(conn, KPM_IOU_REQ_TYPE_SEND_ZC));
}

static void worker_iou_send(struct worker_state *self, struct connection *conn,
			    unsigned int events)
{
	while (self->iou_sends < IOU_PENDING_SENDS) {
		if (self->iou_opts.send_zc)
			worker_iou_send_zc(self, conn);
		else
			__worker_iou_send(self, conn);
		self->iou_sends++;
	}
}

static void
worker_handle_send(struct worker_state *self, struct connection *conn,
		   unsigned int events)
{
	unsigned int rep = max_t(int, 10, conn->to_send / conn->write_size + 1);
	int flags = conn->spec->msg_zerocopy ? MSG_ZEROCOPY : 0;

	while (rep--) {
		void *src = &patbuf[conn->tot_sent % PATTERN_PERIOD];
		size_t chunk;
		ssize_t n;

		chunk = min_t(size_t, conn->write_size, conn->to_send);
		n = send(conn->fd, src, chunk, MSG_DONTWAIT | flags);
		if (n == 0) {
			warnx("zero send chunk:%zd to_send:%lld to_recv:%lld",
			      chunk, conn->to_send, conn->to_recv);
			worker_kill_conn(self, conn);
			return;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				kpm_dbg("send full (0 sent)");
				worker_send_arm(self, conn, events);
				return;
			}
			warn("Send failed");
			worker_kill_conn(self, conn);
			return;
		}

		conn->to_send -= n;
		conn->tot_sent += n;
		if (conn->spec->msg_zerocopy) {
			conn->to_send_comp += 1;
			kpm_dbg("queued send completion, total %d",
				conn->to_send_comp);
		}

		if (!conn->to_send && !conn->to_send_comp) {
			worker_send_finished(self, conn, events);
			break;
		}

		if (n != (ssize_t)chunk) {
			kpm_dbg("send full (partial)");
			worker_send_arm(self, conn, events);
			return;
		}
	}
}

static void
worker_handle_recv(struct worker_state *self, struct connection *conn)
{
	int flags = conn->spec->msg_trunc ? MSG_TRUNC : 0;
	unsigned int rep = 10;
	unsigned char *buf;

	buf = malloc(conn->read_size);
	if (!buf) {
		warnx("No memory");
		return;
	}

	while (rep--) {
		size_t chunk;
		ssize_t n;

		chunk = min_t(size_t, conn->read_size, conn->to_recv);
		n = recv(conn->fd, buf, chunk, MSG_DONTWAIT | flags);
		if (n == 0) {
			warnx("zero recv");
			worker_kill_conn(self, conn);
			break;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;;
			warn("Recv failed");
			worker_kill_conn(self, conn);
			break;
		}

		if (self->memcmp) {
			void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
			if (!conn->spec->msg_trunc && memcmp(buf, src, n))
				warnx("Data corruption %d %d %ld %lld %lld %d",
				      *buf, *(char *)src, n,
				      conn->tot_recv % PATTERN_PERIOD,
				      conn->tot_recv, rep);
		}

		conn->to_recv -= n;
		conn->tot_recv += n;

		if (!conn->to_recv) {
			worker_recv_finished(self, conn);
			if (conn->to_send) {
				worker_handle_send(self, conn, 0);
				break;
			}
		}

		if (n != conn->read_size)
			break;
	}

	free(buf);
}

static void
worker_handle_conn(struct worker_state *self, int fd, unsigned int events)
{
	static int warnd_unexpected_pi;
	struct connection *conn;

	conn = worker_find_connection_by_fd(self, fd);

	if (events & EPOLLOUT) {
		if (conn->to_send)
			worker_handle_send(self, conn, events);
		else if (!conn->to_send_comp)
			worker_send_disarm(self, conn, events);
	}
	if (events & EPOLLIN) {
		if (conn->to_recv) {
			worker_handle_recv(self, conn);
		} else if (!warnd_unexpected_pi) {
			warnx("Unexpected POLLIN %x", events);
			warnd_unexpected_pi = 1;
		}
	}
	if (events & EPOLLERR)
		worker_handle_completions(self, conn, events);

	if (!(events & (EPOLLOUT | EPOLLIN | EPOLLERR)))
		warnx("Connection has nothing to do %x", events);
}

static int worker_prep(struct worker_state *self)
{
	struct epoll_event ev;

	self->epollfd = epoll_create1(0);
	if (self->epollfd < 0)
		err(5, "Failed to create epoll");

	ev.events = EPOLLIN;
	ev.data.fd = self->main_sock;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, self->main_sock, &ev) < 0)
		err(6, "Failed to init epoll");

	return 0;
}

static void worker_wait(struct worker_state *self)
{
	struct epoll_event events[32];
	int i, nfds;

	nfds = epoll_wait(self->epollfd, events, ARRAY_SIZE(events), -1);
	if (nfds < 0)
		err(7, "Failed to epoll");

	for (i = 0; i < nfds; i++) {
		struct epoll_event *e = &events[i];

		if (e->data.fd == self->main_sock)
			worker_handle_main_sock(self);
		else
			worker_handle_conn(self, e->data.fd, e->events);
	}
}

static void worker_add_test(struct worker_state *self, struct connection *conn)
{
	struct epoll_event ev = {};
	int zc;

	zc = !!conn->spec->msg_zerocopy;
	if (setsockopt(conn->fd, SOL_SOCKET, SO_ZEROCOPY, &zc, sizeof(zc))) {
		warnx("Failed to set SO_ZEROCOPY");
		self->quit = 1;
		return;
	}

	ev.events = EPOLLIN | EPOLLOUT;
	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, conn->fd, &ev) < 0)
		warn("Failed to modify poll out");
}

static void worker_stop_test(struct worker_state *self, struct connection *conn)
{
	struct epoll_event ev = {};

	ev.data.fd = conn->fd;
	if (epoll_ctl(self->epollfd, EPOLL_CTL_DEL, conn->fd, &ev) < 0)
		warn("Failed to del poll out");
}

static void
worker_setup_fptrs(struct worker_state *self)
{
	self->prep = worker_prep;
	self->wait = worker_wait;
	self->add_test = worker_add_test;
	self->stop_test = worker_stop_test;
}

static void worker_iou_handle_proto_hdr(struct worker_state *self, struct kpm_state *state, struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *sqe;
	struct kpm_header *hdr;
	size_t n;

	n = cqe->res;
	if (n < sizeof(struct kpm_header))
		errx(2, "handle main sock recv size too small");
	hdr = (struct kpm_header *)state->buf;

	if (hdr->len < sizeof(struct kpm_header))
		errx(2, "handle main sock invalid header len");
	state->len = n;

	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_recv(sqe, self->main_sock, state->buf + n, (hdr->len - n), 0);
	io_uring_sqe_set_data(sqe, tag(state, KPM_IOU_REQ_TYPE_MAIN));
}

static void worker_iou_handle_proto(struct worker_state *self, struct kpm_state *state, struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *sqe;
	struct kpm_header *hdr;
	size_t n;
	int i;

	n = cqe->res;
	hdr = (struct kpm_header *)state->buf;
	if (state->len + n < hdr->len)
		errx(2, "not got full frame");

	for (i = 0; i < (int)ARRAY_SIZE(msg_handlers); i++) {
		if (msg_handlers[i].type != hdr->type)
			continue;

		if (hdr->len < msg_handlers[i].req_size) {
			warn("Invalid request for %s", msg_handlers[i].name);
			self->quit = 1;
			break;
		}

		msg_handlers[i].cb(self, hdr);
		break;
	}
	if (i == (int)ARRAY_SIZE(msg_handlers)) {
		warnx("Unknown message type: %d", hdr->type);
		self->quit = 1;
	}

	if (hdr->type == KPM_MSG_WORKER_END_TEST) {
		self->quit = 1;
		return;
	}
	
	memset(state, 0, sizeof(*state));
	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_recv(sqe, self->main_sock, state->buf, sizeof(struct kpm_header), 0);
	io_uring_sqe_set_data(sqe, tag(state, KPM_IOU_REQ_TYPE_MAIN));
}

static void
worker_iou_handle_main_sock(struct worker_state *self,
			    struct io_uring_cqe *cqe)
{
	struct kpm_state *state;

	if (cqe->res < 0)
		errx(2, "handle main sock recv err: %d", cqe->res);
	// EOF
	if (cqe->res == 0)
		return;

	state = untag(cqe->user_data);
	if (!state->len)
		worker_iou_handle_proto_hdr(self, state, cqe);
	else
		worker_iou_handle_proto(self, state, cqe);
}

static void worker_iou_handle_read(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *sqe;
	struct connection *conn;
	ssize_t n;
	size_t chunk;

	if (!self->test)
		return;

	conn = untag(cqe->user_data);

	if (cqe->res <= 0) {
		warn("recv error: res=%d", cqe->res);
		worker_kill_conn(self, conn);
		return;
	}

	n = cqe->res;
	if (self->memcmp) {
		void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
		if (memcmp(conn->buf, src, n))
			warnx("Data corruption %d %d %ld %lld %lld",
			*conn->buf, *(char *)src, n,
			conn->tot_recv % PATTERN_PERIOD,
			conn->tot_recv);
	}

	conn->to_recv -= n;
	conn->tot_recv += n;
	if (!conn->to_recv) {
		worker_recv_finished(self, conn);
		if (conn->to_send)
			errx(1, "Unexpected to_send w/ recv");
	}
	/*
	if (n != conn->read_size)
		errx(1, "recv size %lu != read_size %u", n, conn->read_size);
	*/

	chunk = min_t(size_t, conn->read_size, conn->to_recv);
	memset(conn->buf, 0, conn->read_size);
	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_recv(sqe, conn->fd, conn->buf, chunk, 0);
	io_uring_sqe_set_data(sqe, tag(conn, KPM_IOU_REQ_TYPE_READ));
}

static unsigned char *iou_zcrx_get_data(struct iou_zcrx *zcrx, uint64_t off)
{
	uint64_t mask = (1ULL << IORING_ZCRX_AREA_SHIFT) - 1;
	return (unsigned char *)zcrx->area_base + (off & mask);
}

static void iou_zcrx_recycle(struct iou_zcrx *zcrx, struct io_uring_cqe *cqe, struct io_uring_zcrx_cqe *rcqe)
{
	struct io_uring_zcrx_rqe* rqe;
	unsigned mask = zcrx->rq_ring.ring_entries - 1;

	rqe = &zcrx->rq_ring.rqes[(zcrx->rq_ring.rq_tail & mask)];
	rqe->off = rcqe->off;
	rqe->len = cqe->res;
	zcrx->rq_ring.rq_tail++;

	IO_URING_WRITE_ONCE(*zcrx->rq_ring.ktail, zcrx->rq_ring.rq_tail);
}

static void worker_iou_add_recvzc(struct io_uring *ring, struct connection *conn)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, conn->fd, NULL, 0, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	io_uring_sqe_set_data(sqe, tag(conn, KPM_IOU_REQ_TYPE_RECVZC));
}

static void worker_iou_add_recv(struct io_uring *ring, struct connection *conn)
{
	struct io_uring_sqe *sqe;
	size_t chunk;

	chunk = min_t(size_t, conn->read_size, conn->to_recv);
	conn->buf = malloc(chunk);
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv(sqe, conn->fd, conn->buf, chunk, 0);
	io_uring_sqe_set_data(sqe, tag(conn, KPM_IOU_REQ_TYPE_READ));
}

static void worker_iou_handle_send(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct connection *conn;
	int n;

	if (!self->test)
		return;

	conn = untag(cqe->user_data);
	self->iou_sends--;
	assert(self->iou_sends >= 0);
	n = cqe->res;

	if (n < 0) {
		warn("Send failed");
		worker_kill_conn(self, conn);
		return;
	}

	conn->to_send -= n;
	conn->tot_sent += n;

	if (!conn->to_send) {
		worker_send_finished(self, conn, 0);
		return;
	} else {
		worker_iou_send(self, conn, 1);
	}
}

static void worker_iou_handle_recvzc(struct worker_state *self, struct io_uring_cqe *cqe)
{
	struct connection *conn;
	ssize_t n;
	struct io_uring_zcrx_cqe* rcqe;
	unsigned char *data;
	struct iou_zcrx *zcrx;

	if (!self->test)
		return;

	zcrx = &self->iou_zcrx;
	conn = untag(cqe->user_data);

	if (cqe->res == 0 && cqe->flags == 0) {
		worker_kill_conn(self, conn);
		return;
	}

	if (cqe->res < 0) {
		warn("recvzc error: res=%d", cqe->res);
		worker_kill_conn(self, conn);
		return;
	}

	if (!(cqe->flags & IORING_CQE_F_MORE))
		worker_iou_add_recvzc(&self->ring, conn);

	rcqe = (struct io_uring_zcrx_cqe*)(cqe + 1);

	n = cqe->res;
	data = iou_zcrx_get_data(zcrx, rcqe->off);

	if (self->memcmp) {
		void *src = &patbuf[conn->tot_recv % PATTERN_PERIOD];
		if (memcmp(data, src, n))
			warnx("Data corruption %d %d %ld %lld %lld",
			*data, *(char *)src, n,
			conn->tot_recv % PATTERN_PERIOD,
			conn->tot_recv);
	}

	conn->to_recv -= n;
	conn->tot_recv += n;

	if (!conn->to_recv) {
		worker_recv_finished(self, conn);
		if (conn->to_send)
			worker_iou_send(self, conn, 1);
	}

	iou_zcrx_recycle(zcrx, cqe, rcqe);
}

static int worker_iou_zcrx_register(struct iou_zcrx *zcrx, struct iou_opts *opts)
{
	void *ring_ptr;
	int errno_copy;
	int ret;

	struct io_uring_zcrx_area_reg area_reg = {
		.addr = (__u64)(unsigned long)zcrx->area_base,
		.len = zcrx->area_size,
		.flags = 0,
		.area_id = 0,
	};

	struct io_uring_zcrx_ifq_reg reg = {
		.if_idx = zcrx->ifindex,
		.if_rxq = opts->zcrx_queue_id,
		.rq_entries = opts->zcrx_rq_entries,
		.area_ptr = (__u64)(unsigned long)&area_reg,
	};

	ret = io_uring_register_ifq(zcrx->ring, &reg);
	if (ret)
		return ret;

	ring_ptr = mmap(0,
			reg.offsets.mmap_sz,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE,
			zcrx->ring->enter_ring_fd,
			IORING_OFF_RQ_RING);
	if (ring_ptr == MAP_FAILED) {
		errno_copy = errno;
		return errno_copy;
	}
	zcrx->ring_ptr = ring_ptr;
	zcrx->ring_size = reg.offsets.mmap_sz;

	zcrx->rq_ring.khead = (unsigned int*)((char*)ring_ptr + reg.offsets.head);
	zcrx->rq_ring.ktail = (unsigned int*)((char*)ring_ptr + reg.offsets.tail);
	zcrx->rq_ring.rqes = (struct io_uring_zcrx_rqe*)((char*)ring_ptr + reg.offsets.rqes);
	zcrx->rq_ring.rq_tail = 0;
	zcrx->rq_ring.ring_entries = reg.rq_entries;

	return 0;
}

static int worker_iou_prep_recvzc(struct worker_state *self, struct iou_opts *opts)
{
	struct iou_zcrx *zcrx = &self->iou_zcrx;
	unsigned int ifindex;
	void *area;
	int ret;

	zcrx->ring = &self->ring;

	ifindex = if_nametoindex(self->iou_opts.dev_name);
	if (!ifindex) {
		err(5, "Bad interface name: %s", self->iou_opts.dev_name);
		return 1;
	}
	zcrx->ifindex = ifindex;

	zcrx->area_size = opts->zcrx_pages * opts->zcrx_page_size;
	printf("----- area_size=%lu\n", zcrx->area_size);
	area = mmap(NULL, zcrx->area_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGE_2MB,
		    -1, 0);
	if (area != MAP_FAILED) {
		printf("----- Using 2MB huge pages\n");
	} else {
		area = mmap(NULL, zcrx->area_size, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	}
	if (area == MAP_FAILED) {
		err(5, "Failed to mmap zero copy area");
		return 1;
	}
	zcrx->area_base = area;

	ret = worker_iou_zcrx_register(zcrx, opts);
	if (ret) {
		err(5, "Failed to register zcrx");
		return ret;
	}

	return 0;
}

static int
worker_iou_prep(struct worker_state *self)
{
	struct iou_opts *opts = &self->iou_opts;
	struct io_uring_params p = {};
	struct io_uring_sqe *sqe;
	int ret;

	if (opts->zcrx && !opts->dev_name)
		err(5, "Need device name for io_uring zero-copy rx");

	p.flags |= IORING_SETUP_CQSIZE;
	p.flags |= IORING_SETUP_COOP_TASKRUN;
	p.flags |= IORING_SETUP_SINGLE_ISSUER;
	p.flags |= IORING_SETUP_DEFER_TASKRUN;
	p.flags |= IORING_SETUP_SUBMIT_ALL;
	p.flags |= IORING_SETUP_R_DISABLED;
	p.flags |= IORING_SETUP_CQE32;

	p.cq_entries = 8192;
	ret = io_uring_queue_init_params(64, &self->ring, &p);
	if (ret < 0)
		err(5, "Failed to create io_uring");

	if (opts->zcrx)
		ret = worker_iou_prep_recvzc(self, opts);

	if (opts->send_zc) {
		struct iovec iov = {
			.iov_base = patbuf,
			.iov_len = PATBUF_SZ,
		};

		ret = io_uring_register_buffers(&self->ring, &iov, 1);
		if (ret < 0)
			err(5, "Failed to register buffers");
	}

	struct kpm_state *state;
	state = malloc(sizeof(*state));
	memset(state, 0, sizeof(*state));

	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_recv(sqe, self->main_sock, state->buf, sizeof(struct kpm_header), 0);
	io_uring_sqe_set_data(sqe, tag(state, KPM_IOU_REQ_TYPE_MAIN));

	// TODO: permutations of options
	// provided buffers
	// fixed files

	io_uring_enable_rings(&self->ring);
	
	return 0;
}

static void
worker_iou_wait(struct worker_state *self)
{
	struct __kernel_timespec timeout;
	unsigned int count = 0;
	unsigned int head;
	struct io_uring_cqe *cqe;

	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;

	io_uring_submit_and_wait_timeout(&self->ring, &cqe, 1, &timeout, NULL);

	io_uring_for_each_cqe(&self->ring, head, cqe) {
		if (cqe->flags & IORING_CQE_F_NOTIF)
			goto next;
		switch (get_tag(cqe->user_data)) {
			case KPM_IOU_REQ_TYPE_MAIN:
				worker_iou_handle_main_sock(self, cqe);
				break;
			case KPM_IOU_REQ_TYPE_READ:
				worker_iou_handle_read(self, cqe);
				break;
			case KPM_IOU_REQ_TYPE_RECVZC:
				worker_iou_handle_recvzc(self, cqe);
				break;
			case KPM_IOU_REQ_TYPE_SEND:
			case KPM_IOU_REQ_TYPE_SEND_ZC:
				worker_iou_handle_send(self, cqe);
				break;
			default:
				err(1, "Unknown io_uring request type: %d, res: %d", get_tag(cqe->user_data), cqe->res);
		}
next:
		count++;
	}
	io_uring_cq_advance(&self->ring, count);
}

static void
worker_iou_add_test(struct worker_state *self, struct connection *conn)
{
	if (self->iou_opts.zcrx) {
		printf("----- add recvzc\n");
		worker_iou_add_recvzc(&self->ring, conn);
	} else {
		printf("----- add recv\n");
		worker_iou_add_recv(&self->ring, conn);
	}
	if (conn->to_send)
		worker_iou_send(self, conn, 1);
}

static void
worker_iou_stop_test(struct worker_state *self, struct connection *conn)
{
	struct io_uring_sqe *sqe;

	printf("----- iou stop_test\n");
	sqe = io_uring_get_sqe(&self->ring);
	io_uring_prep_cancel_fd(sqe, conn->fd, 0);
	// FIXME: called from worker_kill_conn() which may not be ending test but only killing a conn
	// need to submit the cancel fd req!
}

static void
worker_setup_iou_fptrs(struct worker_state *self)
{
	self->prep = worker_iou_prep;
	self->wait = worker_iou_wait;
	self->add_test = worker_iou_add_test;
	self->stop_test = worker_iou_stop_test;
}

/* == Main loop == */

void NORETURN pworker_main(int fd, struct server_opts *opts)
{
	struct worker_state self = { .main_sock = fd, };
	unsigned char j;
	int i, ret;
	void *ptr;

	if (posix_memalign(&ptr, 4096, PATBUF_SZ))
		exit(0);
	patbuf = ptr;

	list_head_init(&self.connections);
	self.memcmp = opts->memcmp;
	self.iou_opts = opts->iou_opts;
	printf("----- worker_main: memcmp=%d\n", self.memcmp);

	if (opts->iou_opts.enable)
		worker_setup_iou_fptrs(&self);
	else
		worker_setup_fptrs(&self);

	/* Initialize the data buffer we send/receive, it must match
	 * on both ends, this is how we catch data corruption (ekhm kTLS..)
	 */
	for (i = 0, j = 0; i < PATBUF_SZ; i++, j++) {
		j = j ?: 1;
		patbuf[i] = j;
	}

	ret = self.prep(&self);
	if (ret)
		err(ret, "Worker failed prep()");

	while (!self.quit) {
		int msec = -1;

		/* Check if we should end the test if we initiated */
		if (self.test && self.test->active) {
			struct timerel t;

			t = timemono_since(self.test_start);
			msec = self.test_len_msec - time_to_msec(t);
			if (msec < 0)
				worker_report_test(&self);
		}

		self.wait(&self);
	}

	kpm_dbg("exiting!");
	// FIXME:io_uring not exiting properly
	if (self.iou_opts.enable)
		io_uring_queue_exit(&self.ring);
	exit(0);
}
