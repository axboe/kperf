/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright Meta Platforms, Inc. and affiliates */

#ifndef SERVER_H
#define SERVER_H 1

#include <netdb.h>
#include <sys/types.h>

#include <ccan/compiler/compiler.h>
#include <ccan/list/list.h>

struct iou_opts {
	bool enable;
	bool zcrx;
	bool send_zc;
	char *dev_name;
	unsigned long zcrx_rq_entries;
	unsigned long zcrx_pages;
	unsigned long zcrx_page_size;
	unsigned long zcrx_queue_id;
};

struct server_opts {
	unsigned int accept_port;
	bool memcmp;
	struct iou_opts iou_opts;
};

struct server_session {
	int cfd;
	pid_t pid;
	struct list_node sessions;
};

struct server_session *
server_session_spawn(int fd, struct sockaddr_in6 *addr, socklen_t *addrlen, struct server_opts *opts);

void NORETURN pworker_main(int fd, struct server_opts *opts);

#endif /* SERVER_H */
