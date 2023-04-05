/*
 * Canny - A simple CAN-over-IP gateway
 * Copyright (C) 2016-2023 Matthias Kruk
 *
 * Canny is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * Canny is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with canny; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/can.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <array.h>
#include <assert.h>
#include <getopt.h>
#include <config.h>
#include "log.h"

#define FLAG_DAEMON 1
#define FLAG_LISTEN 2

#define SHORTOPTS   "dc:p:hvq"

static const struct option cmd_opts[] = {
	{ "dont-fork", no_argument,       0, 'd' },
	{ "connect",   required_argument, 0, 'c' },
	{ "port",      required_argument, 0, 'p' },
	{ "help",      no_argument,       0, 'h' },
	{ "verbose",   no_argument,       0, 'v' },
	{ "quiet",     no_argument,       0, 'q' },
	{ 0, 0, 0, 0 }
};

struct connection {
	int fd;
	struct sockaddr *addr;
	socklen_t addr_size;

	void (*input_event)(struct connection*);
	void (*close_event)(struct connection*);
};

struct in6_connection {
	struct connection conn;
	struct sockaddr_in6 addr;

	union {
		struct can_frame frame[CONFIG_BUFFER_FRAMES];
		unsigned char raw[CONFIG_BUFFER_FRAMES * sizeof(struct can_frame)];
	} __attribute__((packed)) data;
	size_t dlen;
};

struct in6_server {
	struct connection conn;
	struct sockaddr_in6 addr;
};

typedef enum {
	CAN_TYPE_20B,
	CAN_TYPE_FD
} can_type_t;

struct can_iface {
	struct connection conn;
	struct sockaddr_can addr;
	char name[32];
	can_type_t type;
	int mtu;
};

static array_t *conns;
static array_t *ifaces;
static int run;
static int epfd;

static void can_input_event(struct can_iface *iface);
static void in6_client_input_event(struct in6_connection *client);
static void in6_client_close_event(struct in6_connection *client);
static void in6_server_input_event(struct in6_server *server);

static int in6connect(const char *host, unsigned short port)
{
	struct addrinfo hints, *res, *p;
	char portstr[6];
	int ret_val, err;

	ret_val = -EHOSTUNREACH;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof(portstr), "%hu", port);

	if((err = getaddrinfo(host, portstr, &hints, &res)) != 0) {
		log_error("getaddrinfo: %s\n", gai_strerror(err));
		ret_val = -ENOENT;
	} else {
		for(p = res; p; p = p->ai_next) {
			int fd;

			if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
				ret_val = -errno;
				log_perror("socket");
				continue;
			}

			if((err = connect(fd, p->ai_addr, p->ai_addrlen)) < 0) {
				ret_val = -errno;
				log_perror("connect");
				close(fd);
			} else {
				ret_val = fd;
				break;
			}
		}

		freeaddrinfo(res);
	}

	return(ret_val);
}

static int in6listen(unsigned short port)
{
	struct sockaddr_in6 addr;
	int err;
	int fd;

	if((fd = socket(PF_INET6, SOCK_STREAM, 0)) < 0) {
		err = errno;
		log_perror("socket");
		return(-err);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	err = 1;

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &err, sizeof(err)) < 0) {
		log_perror("setsockopt");
	}

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		err = errno;
		log_perror("bind");
		close(fd);
		return(-err);
	}

	if(listen(fd, CONFIG_INET_BACKLOG) < 0) {
		err = errno;
		log_perror("listen");
		close(fd);
		return(-err);
	}

	return(fd);
}

static struct in6_server* in6_server(unsigned short port)
{
	struct in6_server *server;
	int fd;

	if((fd = in6listen(port)) < 0) {
		return NULL;
	}

	if (!(server = calloc(1, sizeof(*server)))) {
		close(fd);
	} else {
		/*
		 * We don't need the address structure, so we don't really
		 * bother that in6listen() does not use the one in the
		 * in6_server we're allocating here. This will need to be
		 * changed in case we ever need the address.
		 */
		server->conn.fd = fd;
		server->conn.addr = (struct sockaddr*)&server->addr;
		server->conn.addr_size = sizeof(server->addr);
		server->conn.input_event = (void(*)(struct connection*))in6_server_input_event;
	}

	return server;
}

static struct in6_connection* in6_client(const char *hostname, unsigned short port)
{
	struct in6_connection *conn;
	int fd;

	if ((fd = in6connect(hostname, port) < 0)) {
		log_error("Unable to connect to %s:%d\n", hostname, port & 0xffff);
		return NULL;
	}

	if (!(conn = calloc(1, sizeof(*conn)))) {
		close(fd);
	} else {
		conn->conn.fd = fd;
		conn->conn.addr = (struct sockaddr*)&conn->addr;
		conn->conn.addr_size = sizeof(conn->addr);
		conn->conn.input_event = (void(*)(struct connection*))in6_client_input_event;
		conn->conn.close_event = (void(*)(struct connection*))in6_client_close_event;
	}

	return conn;
}

static int cansock(int ifindex)
{
	struct sockaddr_can addr;
	int result;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifindex;

	if ((fd = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		result = -errno;
		log_perror("socket");
	} else if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		result = -errno;
		log_perror("bind");
		close(fd);
	} else {
		result = fd;
	}

	return result;
}

static int watch_fd(int fd, void *data)
{
	struct epoll_event ev;
	int err;

	memset(&ev, 0, sizeof(ev));
	ev.data.ptr = data;
	ev.events = EPOLLIN;
	err = 0;

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		log_perror("epoll_ctl");
		err = 1;
	}

	return err;
}

static int get_iface_mtu(const char *ifname)
{
        struct ifreq ifr;
        int ret_val;
        int fd;

        if ((fd = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
                ret_val = -errno;
                log_perror("socket");
        } else {
                memset(&ifr, 0, sizeof(ifr));
                snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

                if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
                        ret_val = -errno;
                        log_perror("ioctl");
                } else {
                        ret_val = ifr.ifr_mtu;
                }

                close(fd);
        }

        return ret_val;
}

static struct can_iface* can_open(const char *ifname, int ifindex)
{
	struct can_iface *iface;
	int fd;

	if ((fd = cansock(ifindex)) < 0) {
		return NULL;
	}

	if (!(iface = calloc(1, sizeof(*iface)))) {
		close(fd);
	} else {
		iface->conn.fd = fd;
		iface->conn.addr = (struct sockaddr*)&iface->addr;
		iface->conn.addr_size = sizeof(iface->addr);
		iface->conn.input_event = (void(*)(struct connection*))can_input_event;
		iface->addr.can_family = AF_CAN;
		iface->addr.can_ifindex = ifindex;
		snprintf(iface->name, sizeof(iface->name), "%s", ifname);

		if ((iface->mtu = get_iface_mtu(iface->name)) < 0) {
			log_warn("Could not determine MTU of %s. Assuming %d.\n", iface->name, CAN_MTU);
			iface->mtu = CAN_MTU;
		}

		switch (iface->mtu) {
		default:
			log_warn("MTU of %s is neither %d nor %d. Assuming CAN2.0B.\n",
				 iface->name, CAN_MTU, CANFD_MTU);
			/* fall-through */
		case CAN_MTU:
			iface->type = CAN_TYPE_20B;
			break;

		case CANFD_MTU:
			iface->type = CAN_TYPE_FD;
			break;
		}
	}

	return iface;
}

static void can_free(struct can_iface *iface)
{
	close(iface->conn.fd);
	free(iface);
}

static int can_init(void)
{
	struct ifreq ifr;
	int fd;
	int err;

	if((fd = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		err = -errno;
		log_perror("socket");
		return err;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = 1;

	while ((err = ioctl(fd, SIOCGIFNAME, &ifr)) >= 0) {
		if (strstr(ifr.ifr_name, "can") != NULL) {
			struct can_iface *iface;

			log_info("Found CAN interface: %s\n", ifr.ifr_name);

			if (!(iface = can_open(ifr.ifr_name, ifr.ifr_ifindex))) {
				log_warn("Could not open interface %s\n", ifr.ifr_name);

			} else if (watch_fd(iface->conn.fd, iface) < 0) {
				log_error("Could not add interface %s (fd %d) to epoll set\n",
					  ifr.ifr_name, iface->conn.fd);
				can_free(iface);

			} else if (array_insert(ifaces, iface) < 0) {
				log_warn("Could not add %s to interface list\n", ifr.ifr_name);
				can_free(iface);

			} else {
				log_info("Listening for messages on %s (fd %d)\n",
					 ifr.ifr_name, iface->conn.fd);
			}
		}

		ifr.ifr_ifindex++;
	}

	close(fd);
	return 0;
}

static void in6_server_free(struct in6_server *server)
{
	close(server->conn.fd);
	free(server);
}

static void in6_connection_free(struct in6_connection *conn)
{
	close(conn->conn.fd);
	free(conn);
}

static int server_init(unsigned short port)
{
	struct in6_server *server;

	if (!(server = in6_server(port & 0xffff))) {
		log_error("Could not listen on port %hu\n", port);
		return 1;

	} else if (watch_fd(server->conn.fd, server) < 0) {
		log_error("Could not add server (fd %d) to epoll set\n", server->conn.fd);
		in6_server_free(server);

	} else {
		log_info("Waiting for clients on port %hu (fd %d)\n", port, server->conn.fd);
	}

	return 0;
}

static int client_init(const char *hostname, unsigned short port)
{
	struct in6_connection *client;

	if (!(client = in6_client(hostname, port))) {
		log_error("Could not connect to %s:%hu\n", hostname, port);
		return 1;

	} else if (watch_fd(client->conn.fd, client) < 0) {
		log_error("Could not add client (fd %d) to epoll set\n", client->conn.fd);
		in6_connection_free(client);
		return 1;

	} else if (array_insert(conns, client) < 0) {
		log_error("Could not add client to connection array\n");
		in6_connection_free(client);
		return 1;

	} else {
		log_info("Connected to %s:%hu (fd %d)\n", hostname, port, client->conn.fd);
	}

	return 0;
}

static void broadcast_can(struct can_frame *frm)
{
	ARRAY_FOREACH(ifaces, struct connection, con, {
		if(sendto(con->fd, frm, sizeof(*frm), 0, con->addr, con->addr_size) < 0) {
			log_perror("sendto");
		}
	});

	return;
}

static void broadcast_net(struct can_frame *frm)
{
	ARRAY_FOREACH(conns, struct connection, con, {
		if(send(con->fd, frm, sizeof(*frm), 0) < 0) {
			log_perror("send");
		}
	});

	return;
}

static void broadcast_net2(struct can_frame *frm, struct connection *src)
{
	ARRAY_FOREACH(conns, struct connection, con, {
		if(con->fd == src->fd) {
			continue;
		}

		if(send(con->fd, frm, sizeof(*frm), 0) < 0) {
			log_perror("send");
		}
	});

	return;
}

static void can_input_event(struct can_iface *iface)
{
	struct can_frame frm;
	int flen;

	if((flen = read(iface->conn.fd, &frm, sizeof(frm))) < 0) {
		log_perror("read");
	} else if(flen == sizeof(frm)) {
		broadcast_net(&frm);
	} else {
		log_error("flen = %d\n", flen);
	}
}

static void in6_client_input_event(struct in6_connection *client)
{
	size_t rsize;
	int len;

	rsize = sizeof(client->data) - client->dlen;
	len = 1;

	if(rsize > 0) {
		len = recv(client->conn.fd, client->data.raw + client->dlen, rsize, 0);

		if(len > 0) {
			client->dlen += len;
		}
	}

	/* broadcast buffered frames */
	if(client->dlen >= sizeof(struct can_frame)) {
		size_t new_dlen;
		int idx;

		idx = 0;
		new_dlen = client->dlen;

		/* send out the frames that were fully buffered */

		while(idx < CONFIG_BUFFER_FRAMES && new_dlen >= sizeof(struct can_frame)) {
			broadcast_can(&(client->data.frame[idx]));
			broadcast_net2(&(client->data.frame[idx]), (struct connection*)client);
			idx++;
			new_dlen -= sizeof(struct can_frame);
		}

		/* if we have a partial frame, move it to the front of the buffer */
		if(new_dlen > 0) {
			memcpy(client->data.raw, client->data.raw + (client->dlen - new_dlen), new_dlen);
		}

		client->dlen = new_dlen;
	}

	if(len <= 0) {
		/* error (-1) or connection closed (0) */
		if (client->conn.close_event) {
			client->conn.close_event((struct connection*)client);
		}

		array_remove(conns, client);
		in6_connection_free(client);
	}
}

static void in6_client_close_event(struct in6_connection *client)
{
	/*
	 * This event is attached only when canny is acting as a client.
	 * When the connection to the server is closed, stop the main loop.
	 */
	log_info("Connection to server (fd %d) closed. Quitting.\n", client->conn.fd);
	run = 0;
}

static void in6_server_input_event(struct in6_server *server)
{
	struct epoll_event nev;
	struct in6_connection *new_client;
	int err;

	if (!(new_client = calloc(1, sizeof(*new_client)))) {
		log_perror("calloc");
	} else {
		new_client->conn.addr = (struct sockaddr*)&new_client->addr;
		new_client->conn.addr_size = sizeof(new_client->addr);
		new_client->conn.fd = accept(server->conn.fd, new_client->conn.addr,
					     &new_client->conn.addr_size);
		new_client->conn.input_event = (void(*)(struct connection*))in6_client_input_event;
		/* don't need the close_event when canny is acting as server */

		if(new_client->conn.fd < 0) {
			free(new_client);
		} else {
			nev.data.ptr = new_client;
			nev.events = EPOLLIN;

			if(epoll_ctl(epfd, EPOLL_CTL_ADD, new_client->conn.fd, &nev) < 0) {
				log_perror("epoll_ctl");
				close(new_client->conn.fd);
				free(new_client);
			} else if((err = array_insert(conns, new_client)) < 0) {
				log_error("array_insert: %s\n", strerror(-err));
				close(new_client->conn.fd);
				free(new_client);
			}
		}
	}
}

static void handle_signal(int sig)
{
	switch(sig) {
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
	case SIGUSR1:
		run = 0;
	default:
		break;
	}

	return;
}

static void sigsetup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_signal;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);

	return;
}

static void print_usage(const char *argv0)
{
	printf("Usage: %s [OPTIONS]\n"
	       "Provide an IP-to-CAN gateway. By default, %s will fork to the background\n"
	       "and listen for incoming connections on port %d.\n"
	       "\n"
	       "The following options are recognized:\n"
	       "  -d, --dont-fork   don't fork to the background\n"
	       "  -c, --connect     connect to the host specified by the next argument\n"
	       "  -p, --port        use the port specified by the next argument\n"
	       "  -h, --help        display this help and exit\n"
	       "  -v, --verbose     be more verbose\n"
	       "  -q, --quiet       be less verbose\n",
	       argv0, CONFIG_MY_NAME, CONFIG_INET_PORT);
}

static int parse_cmdline(int argc, char *argv[], int *flags, int *port, char **hostname)
{
	int option;

	do {
		option = getopt_long(argc, argv, SHORTOPTS, cmd_opts, NULL);

		switch (option) {
		case 'd':
			*flags &= ~FLAG_DAEMON;
			break;

		case 'c':
			*flags &= ~FLAG_LISTEN;
			*hostname = optarg;
			break;

		case 'p':
			*port = strtol(optarg, NULL, 10);

			if(*port > (1 << 16) || errno == ERANGE) {
				log_error("Invalid port specified\n");
				return -ERANGE;
			}
			break;

		case 'h':
			print_usage(argv[0]);
			return -1;

		case 'v':
			log_increase_verbosity(1);
			break;

		case 'q':
			log_increase_verbosity(-1);
			break;

		case '?':
		        log_error("Unrecognized command line option `%s'\n", optarg);
			return -EINVAL;

		default:
			option = -1;
		}
	} while (option >= 0);

	return 0;
}

int main(int argc, char *argv[])
{
	struct epoll_event ev[CONFIG_EPOLL_INITSIZE];
	char *hostname;
	int port;
	int ret_val;
	int flags;

	port = CONFIG_INET_PORT;
	flags = FLAG_DAEMON | FLAG_LISTEN;
	hostname = NULL;
	ret_val = 1;
	run = 1;

	if (parse_cmdline(argc, argv, &flags, &port, &hostname) < 0) {
		return 1;
	}

	if(!(conns = array_alloc())) {
		log_error("Not enough memory for connection array\n");
		return(1);
	}
	if(!(ifaces = array_alloc())) {
		log_error("Not enough memory for interface array\n");
		return(1);
	}

	ret_val = 1;

	if(flags & FLAG_DAEMON) {
		int pid;

		pid = fork();

		if(pid > 0) {
			return(0);
		} else if(pid < 0) {
			log_perror("fork");
			return(1);
		}

		setsid();
	}
	sigsetup();

	if ((epfd = epoll_create(CONFIG_EPOLL_INITSIZE)) < 0) {
		log_perror("epoll_create");
		return(1);
	}

	if(can_init() < 0) {
		log_error("Failed to initialize CAN sockets\n");
		return(1);
	}

	if(flags & FLAG_LISTEN) {
		if (server_init(port & 0xffff) < 0) {
			return 1;
		}
	} else {
		if (client_init(hostname, port & 0xffff) < 0) {
			return 1;
		}
	}

	while(run) {
		int n;

		n = epoll_wait(epfd, ev, CONFIG_EPOLL_INITSIZE, -1);

		while(--n >= 0) {
			struct connection *con;

			con = ev[n].data.ptr;

			if (!con->input_event) {
				continue;
			}
			con->input_event(con);
		}
	}

	close(epfd);

	return(ret_val);
}
