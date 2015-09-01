/*      $Id: filter.c,v 1.2 2006/10/16 19:58:50 bcarnazzi Exp $ */

/*
 * Copyright (c) 2006, 2007 Bruno Carnazzi, <bcarnazzi@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "filter.h"

/* From netinet/in.h, but only _KERNEL_ gets them. */
#define satosin(sa)     ((struct sockaddr_in *)(sa))
#define satosin6(sa)    ((struct sockaddr_in6 *)(sa))

void init_filter(void);
int server_lookup(struct sockaddr *, struct sockaddr *, struct sockaddr *,
        u_int8_t);
int server_lookup4(struct sockaddr_in *, struct sockaddr_in *,
        struct sockaddr_in *, u_int8_t);
int server_lookup6(struct sockaddr_in6 *, struct sockaddr_in6 *,
        struct sockaddr_in6 *, u_int8_t);

static int dev;

void
init_filter(void)
{
    struct pf_status status;

    dev = open("/dev/pf", O_RDWR);
    if (dev == -1) {
        syslog(LOG_ERR, "cannot open /dev/pf");
        exit(1);
    }
    if (ioctl(dev, DIOCGETSTATUS, &status) == -1) {
        syslog(LOG_ERR, "cannot get pf status");
        exit(1);
    }
    if (!status.running) {
        syslog(LOG_ERR, "pf is not running");
        exit(1);
    }
}

int
server_lookup(struct sockaddr *client, struct sockaddr *proxy,
    struct sockaddr *server, u_int8_t proto)
{
    if (client->sa_family == AF_INET)
        return (server_lookup4(satosin(client), satosin(proxy),
            satosin(server), proto));

    if (client->sa_family == AF_INET6)
        return (server_lookup6(satosin6(client), satosin6(proxy),
            satosin6(server), proto));

    errno = EPROTONOSUPPORT;
    return (-1);
}

int
server_lookup4(struct sockaddr_in *client, struct sockaddr_in *proxy,
    struct sockaddr_in *server, u_int8_t proto)
{
    struct pfioc_natlook pnl;

    memset(&pnl, 0, sizeof pnl);
    pnl.direction = PF_OUT;
    pnl.af = AF_INET;
    pnl.proto = proto;
    memcpy(&pnl.saddr.v4, &client->sin_addr.s_addr, sizeof pnl.saddr.v4);
    memcpy(&pnl.daddr.v4, &proxy->sin_addr.s_addr, sizeof pnl.daddr.v4);
    pnl.sport = client->sin_port;
    pnl.dport = proxy->sin_port;

    if (ioctl(dev, DIOCNATLOOK, &pnl) == -1)
        return (-1);

    memset(server, 0, sizeof(struct sockaddr_in));
    server->sin_len = sizeof(struct sockaddr_in);
    server->sin_family = AF_INET;
    memcpy(&server->sin_addr.s_addr, &pnl.rdaddr.v4,
        sizeof server->sin_addr.s_addr);
    server->sin_port = pnl.rdport;

    return (0);
}

int
server_lookup6(struct sockaddr_in6 *client, struct sockaddr_in6 *proxy,
    struct sockaddr_in6 *server, u_int8_t proto)
{
    struct pfioc_natlook pnl;

    memset(&pnl, 0, sizeof pnl);
    pnl.direction = PF_OUT;
    pnl.af = AF_INET6;
    pnl.proto = proto;
    memcpy(&pnl.saddr.v6, &client->sin6_addr.s6_addr, sizeof pnl.saddr.v6);
    memcpy(&pnl.daddr.v6, &proxy->sin6_addr.s6_addr, sizeof pnl.daddr.v6);
    pnl.sport = client->sin6_port;
    pnl.dport = proxy->sin6_port;
    
    if (ioctl(dev, DIOCNATLOOK, &pnl) == -1)
        return (-1);

    memset(server, 0, sizeof(struct sockaddr_in6));
    server->sin6_len = sizeof(struct sockaddr_in6);
    server->sin6_family = AF_INET6;
    memcpy(&server->sin6_addr.s6_addr, &pnl.rdaddr.v6,
        sizeof server->sin6_addr);
    server->sin6_port = pnl.rdport;

    return (0);
}
