/*                                                                                                                                             
 * Canny - A simple CAN-over-IP gateway
 * Copyright (C) 2016 Matthias Kruk                                                                                                            
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
#include <config.h>

#define FLAG_DAEMON 1
#define FLAG_LISTEN 2

struct conn {
	int fd;
	struct sockaddr_in6 addr;

	union {
		struct can_frame frame[CONFIG_BUFFER_FRAMES];
		unsigned char raw[CONFIG_BUFFER_FRAMES * sizeof(struct can_frame)];
	} __attribute__((packed)) data;
	size_t dlen;
};

struct can_iface {
	int fd;
	struct sockaddr_can addr;
};

static array_t *conns;
static array_t *ifaces;
static int run;

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
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		ret_val = -ENOENT;
	} else {
		for(p = res; p; p = p->ai_next) {
			int fd;

			if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
				ret_val = -errno;
				perror("socket");
				continue;
			}

			if((err = connect(fd, p->ai_addr, p->ai_addrlen)) < 0) {
				ret_val = -errno;
				perror("connect");
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
		perror("socket");
		return(-err);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	err = 1;
	
	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &err, sizeof(err)) < 0) {
		perror("setsockopt");
	}

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		err = errno;
		perror("bind");
		close(fd);
		return(-err);
	}

	if(listen(fd, CONFIG_INET_BACKLOG) < 0) {
		err = errno;
		perror("listen");
		close(fd);
		return(-err);
	}

	return(fd);
}

static int cansock(void)
{
	struct sockaddr_can addr;
	struct ifreq ifr;
	int fd;
	int res;
	int e;

	if(!(ifaces = array_alloc())) {
		return(-1);
	}

	if((fd = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		e = errno;
		perror("socket");
		errno = e;
		return(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;

	if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		e = errno;
		perror("bind");
		close(fd);
		free(ifaces);
		ifaces = NULL;
		errno = e;
		return(-1);
	}
	
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = 1;
	
	do {
		if((res = ioctl(fd, SIOCGIFNAME, &ifr)) >= 0) {
			if(strstr(ifr.ifr_name, "can") != NULL) {
				struct can_iface *iface;

				if((iface = malloc(sizeof(*iface)))) {
					memset(iface, 0, sizeof(*iface));
					
					iface->fd = fd;
					iface->addr.can_ifindex = ifr.ifr_ifindex;
					iface->addr.can_family = AF_CAN;

					if(array_insert(ifaces, iface) < 0) {
						free(iface);
					}
				}
			}
		}
		ifr.ifr_ifindex++;
	} while(res >= 0);

	return(fd);
}

static void broadcast_can(struct can_frame *frm)
{
	ARRAY_FOREACH(ifaces, struct can_iface, iface, {
			if(sendto(iface->fd, frm, sizeof(*frm), 0, (struct sockaddr*)&(iface->addr), sizeof(iface->addr)) < 0) {
				perror("sendto");
			}
		});
	
	return;
}

static void broadcast_net(struct can_frame *frm)
{
	ARRAY_FOREACH(conns, struct conn, con, {
			if(send(con->fd, frm, sizeof(*frm), 0) < 0) {
				perror("send");
			}
		});
	
	return;
}

static void broadcast_net2(struct can_frame *frm, struct conn *src)
{
	ARRAY_FOREACH(conns, struct conn, con, {
			if(con->fd == src->fd) {
				continue;
			}

			if(send(con->fd, frm, sizeof(*frm), 0) < 0) {
				perror("send");
			}
		});
	
	return;
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

int main(int argc, char *argv[])
{
	struct epoll_event ev[CONFIG_EPOLL_INITSIZE];
	char *hostname;
	int port;
	int epfd;
	int netfd;
	int canfd;
	int ret_val;
	int flags;
	int err;

	port = CONFIG_INET_PORT;
	flags = FLAG_DAEMON | FLAG_LISTEN;
	hostname = NULL;
	ret_val = 1;
	run = 1;
	
	for(ret_val = 1; ret_val < argc; ret_val++) {
		if(strcmp(argv[ret_val], "--dont-fork") == 0 || strcmp(argv[ret_val], "-d") == 0) {
			flags &= ~FLAG_DAEMON;
		} else if(strcmp(argv[ret_val], "--connect") == 0 || strcmp(argv[ret_val], "-c") == 0) {
			if(++ret_val < argc) {
				flags &= ~FLAG_LISTEN;
				hostname = argv[ret_val];
			} else {
				fprintf(stderr, "Expected destination after --connect\n");
				return(1);
			}
		} else if(strcmp(argv[ret_val], "--port") == 0 || strcmp(argv[ret_val], "-p") == 0) {
			if(++ret_val < argc) {
				port = strtol(argv[ret_val], NULL, 10);

				if(port > (1 << 16) || errno == ERANGE) {
					fprintf(stderr, "Invalid port specified\n");
					return(1);
				}
			} else {
				fprintf(stderr, "Expected port number after --port\n");
				return(1);
			}
		} else if(strcmp(argv[ret_val], "--help") == 0 || strcmp(argv[ret_val], "-h") == 0) {
			printf("Usage: %s [OPTIONS]\n"
				   "Provide an IP-to-CAN gateway. By default, %s will fork to the background\n"
				   "and listen for incoming connections on port %d.\n"
				   "\n"
				   "The following options are recognized:\n"
				   "  -d, --dont-fork   don't fork to the background\n"
				   "  -c, --connect     connect to the host specified by the next argument\n"
				   "  -p, --port        use the port specified by the next argument\n"
				   "  -h, --help        display this help and exit\n",
				   argv[0], CONFIG_MY_NAME, CONFIG_INET_PORT);
			return(1);
		}
	}

	if(!(conns = array_alloc())) {
		perror("array_alloc");
		return(1);
	}

	ret_val = 1;

	if(flags & FLAG_DAEMON) {
		int pid;

		pid = fork();

		if(pid > 0) {
			return(0);
		} else if(pid < 0) {
			perror("fork");
			return(1);
		}
		
		setsid();
	}
	sigsetup();

	if((canfd = cansock()) < 0) {
		fprintf(stderr, "Failed to initialize CAN socket\n");
		return(1);
	}

	if((epfd = epoll_create(CONFIG_EPOLL_INITSIZE)) < 0) {
		perror("epoll_create");
		close(canfd);
		return(1);
	} else {
		ev[0].data.ptr = &canfd;
		ev[0].events = EPOLLIN;

		if(epoll_ctl(epfd, EPOLL_CTL_ADD, canfd, &ev[0]) < 0) {
			perror("epoll_ctl");
			close(epfd);
			close(canfd);
			return(1);
		}
	}
	
	if(flags & FLAG_LISTEN) {
		if((netfd = in6listen(port & 0xffff)) >= 0) {
			ev[0].data.ptr = &netfd;
			ev[0].events = EPOLLIN;

			if(epoll_ctl(epfd, EPOLL_CTL_ADD, netfd, &ev[0]) < 0) {
				perror("epoll_ctl");
				ret_val = -1;
			} else{
				while(run) {
					int n = epoll_wait(epfd, ev, CONFIG_EPOLL_INITSIZE, -1);

					while(--n >= 0) {
						struct conn *con;

						con = ev[n].data.ptr;

						/* If con->fd is netfd or canfd, don't use any other members of con!
						   In these cases, con really points to just an int, not a struct conn! */

						if(con->fd == netfd) {
							/* new TCP connection -> set up connection */
						
							struct epoll_event nev;
							struct conn *new_con;
							socklen_t addrlen;

							if(!(new_con = malloc(sizeof(*new_con)))) {
								perror("malloc");
							} else {
								new_con->fd = accept(con->fd, (struct sockaddr*)&(new_con->addr), &addrlen);

								if(new_con->fd < 0) {
									free(new_con);
								} else {
									nev.data.ptr = new_con;
									nev.events = EPOLLIN;

									if(epoll_ctl(epfd, EPOLL_CTL_ADD, new_con->fd, &nev) < 0) {
										perror("epoll_ctl");
										close(new_con->fd);
										free(new_con);
									} else if((err = array_insert(conns, new_con)) < 0) {
										fprintf(stderr, "array_insert: %s\n", strerror(-err));
										close(new_con->fd);
										free(new_con);
									}									
								}
							}
						} else if(con->fd == canfd) {
							/* message from CAN bus -> broadcast to TCP clients */

							struct can_frame frm;
							int flen;

							if((flen = read(con->fd, &frm, sizeof(frm))) < 0) {
								perror("read");
							} else if(flen == sizeof(frm)) {
								broadcast_net(&frm);
							} else {
								fprintf(stderr, "flen = %d\n", flen);
							}
						} else {
							/* message from TCP client -> broadcast to TCP clients and CAN bus */

							size_t rsize;
							int rd;
						
							rsize = sizeof(con->data) - con->dlen;

							if(rsize > 0) {
								rd = recv(con->fd, con->data.raw + con->dlen, rsize, 0);

								if(rd > 0) {
									con->dlen += rd;
								}
							}

							/* broadcast buffered frames */
							if(con->dlen >= sizeof(struct can_frame)) {
								size_t new_dlen;
								int idx;

								idx = 0;
								new_dlen = con->dlen;
							
								/* send out the frames that were fully buffered */
							
								while(idx < CONFIG_BUFFER_FRAMES && new_dlen >= sizeof(struct can_frame)) {
									broadcast_can(&(con->data.frame[idx]));
									broadcast_net2(&(con->data.frame[idx]), con);
									idx++;
									new_dlen -= sizeof(struct can_frame);
								}

								/* if we have a partial frame, move it to the front of the buffer */
								if(new_dlen > 0) {
									memcpy(con->data.raw, con->data.raw + (con->dlen - new_dlen), new_dlen);
								}
							
								con->dlen = new_dlen;
							}

							if(rd <= 0) {
								/* error (-1) or connection closed (0) */
								array_remove(conns, con);
								close(con->fd);
								free(con);
							}
						}
					}
				} /* while(run) */
			}
			close(netfd);
		}
	} else { /* if(flags & FLAG_LISTEN) */
		if((netfd = in6connect(hostname, port & 0xffff)) < 0) {
			fprintf(stderr, "Unable to connect to %s:%d\n", hostname, port & 0xffff);
		} else {
			ev[0].data.ptr = &netfd;
			ev[0].events = EPOLLIN;

			if(epoll_ctl(epfd, EPOLL_CTL_ADD, netfd, &ev[0]) < 0) {
				perror("epoll_ctl");
			} else {
				union {
					struct can_frame frame[CONFIG_BUFFER_FRAMES];
					unsigned char raw[CONFIG_BUFFER_FRAMES * sizeof(struct can_frame)];
				} buffer;
				size_t dlen;
				int n;

				dlen = 0;

				while(run) {
					n = epoll_wait(epfd, ev, CONFIG_EPOLL_INITSIZE, -1);

					while(--n >= 0) {
						int fd = *((int*)ev[n].data.ptr);
						int len;
						
						if(fd == canfd) {
							struct can_frame frm;

							len = read(fd, &frm, sizeof(frm));

							if(len == sizeof(frm)) {
								if(send(netfd, &frm, sizeof(frm), 0) < 0) {
									perror("send");
									close(netfd);
									run = 0;
								}
							}
						} else {
							size_t rsize;
						
							rsize = sizeof(buffer) - dlen;

							if(rsize > 0) {
								len = recv(netfd, buffer.raw + dlen, rsize, 0);

								if(len > 0) {
									dlen += len;
								}
							}

							/* broadcast buffered frames */
							if(dlen >= sizeof(struct can_frame)) {
								size_t new_dlen;
								int idx;

								idx = 0;
								new_dlen = dlen;
							
								/* send out the frames that were fully buffered */
							
								while(idx < CONFIG_BUFFER_FRAMES && new_dlen >= sizeof(struct can_frame)) {
									broadcast_can(&(buffer.frame[idx]));
									idx++;
									new_dlen -= sizeof(struct can_frame);
								}

								/* if we have a partial frame, move it to the front of the buffer */
								if(new_dlen > 0) {
									memcpy(buffer.raw, buffer.raw + (dlen - new_dlen), new_dlen);
								}
							
								dlen = new_dlen;
							}

							if(len <= 0) {
								/* error (-1) or connection closed (0) */
								close(netfd);
								run = 0;
							}
						}
					}
				}
			}
		}
	}

	close(epfd);
	close(canfd);
	
	return(ret_val);
}
