/*      $Id: pptp-proxy.c,v 1.17 2006/10/18 19:39:49 bcarnazzi Exp $ */

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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include "filter.h"
#include "rfc2637.h"

#define BUFLEN 1024
#define MAX_LOGLINE 300
#define NTOP_BUFS   3
#define TCP_BACKLOG 10

#define CHROOT_DIR  "/var/empty"
#define NOPRIV_USER "proxy"

#define sstosa(ss)  ((struct sockaddr *)(ss))

void client_error(struct bufferevent *, short, void *);
void client_read(struct bufferevent *, void *);
void client_write(struct bufferevent *, void *);
int drop_privs(void);
int exit_daemon(void);
void handle_connection(const int, short, void *);
void handle_signal(const int, short, void *);
int init_session(void);
void logmsg(int, const char *, ...);
int setnonblock(int);
const char *sock_ntop(struct sockaddr *);
void usage(void);

char ntop_buf[NTOP_BUFS][INET6_ADDRSTRLEN];

struct bufferevent *client_bufev;
struct sockaddr_storage fixed_server_ss, fixed_proxy_ss;
int daemonize, ipv6_mode, loglevel, max_sessions, session_count, session_id, timeout;
char *fixed_server, *fixed_server_port, *fixed_proxy, *listen_ip, *listen_port;

extern char *__progname;

void
client_error(struct bufferevent *bufev, short what, void *arg)
{
    if (what & EVBUFFER_EOF)
        logmsg(LOG_INFO, "client close");
    else if (what == (EVBUFFER_ERROR | EVBUFFER_READ))
        logmsg(LOG_ERR, "client reset connection");
    else if (what & EVBUFFER_TIMEOUT)
        logmsg(LOG_ERR, "client timeout");
    else if (what & EVBUFFER_WRITE)
        logmsg(LOG_ERR, "client write error: %d", what);
    else
        logmsg(LOG_ERR, "abnormal client error: %d", what);

    /* TODO(bcarnazzi): implement a end_session function */
    exit(1);
}

void
client_read(struct bufferevent *bufev, void *arg)
{
    char buf[BUFLEN];
    int n, p;
    n = bufferevent_read(bufev, buf, BUFLEN);
    p = bufferevent_write(bufev, buf, n);

    logmsg(LOG_DEBUG, "client read %d bytes (%d write)", n, p);
}

void
client_write(struct bufferevent *bufev, void *arg)
{
}

int
drop_privs(void)
{
    struct passwd *pw;

    pw = getpwnam(NOPRIV_USER);
    if (pw == NULL)
        return(-1);

    if (chroot(CHROOT_DIR) != 0 || chdir("/") != 0 ||
            setgroups(1, &pw->pw_gid) != 0 ||
            setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0 ||
            setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
        return(-1);

    return(0);
}

int
exit_daemon(void)
{
    if (daemonize)
        closelog();

    exit(0);
}

void
handle_connection(const int listen_fd, short event, void *ev)
{
    struct sockaddr_storage client_ss, client_to_proxy_ss, proxy_to_server_ss, server_ss;
    struct sockaddr *client_sa, *client_to_proxy_sa, *proxy_to_server_sa, *server_sa, *fixed_server_sa, *fixed_proxy_sa;
    socklen_t len;
    int client_fd, on, server_fd, session_id;
    
    /*
     * We _must_ accept the connection, otherwise libevent will keep
     * coming back, and we will chew up all CPU.
     */
    client_sa = sstosa(&client_ss);
    len = sizeof(struct sockaddr_storage);
    if ((client_fd = accept(listen_fd, client_sa, &len)) < 0) {
        logmsg(LOG_CRIT, "accept failed: %s", strerror(errno));
        return;
    }

    /* Refuse connection if the maximum is reached. */
    if (session_count >= max_sessions) {
        logmsg(LOG_ERR, "client limit (%d) reached, refusing "
                "connection from %s", max_sessions, sock_ntop(client_sa));
        close(client_fd);
        return;
    }

    /* Allocate session. */
    session_id = init_session();

    client_to_proxy_sa = sstosa(&client_to_proxy_ss);
    proxy_to_server_sa = sstosa(&proxy_to_server_ss);
    server_sa = sstosa(&server_ss);
    fixed_server_sa = sstosa(&fixed_server_ss);
    fixed_proxy_sa = sstosa(&fixed_proxy_ss);
    
    /* Log id/client early to ease debugging. */
    logmsg(LOG_DEBUG, "#%d accepted connection from %s", session_id,
            sock_ntop(client_sa));

    /*
     * Find out the real server and port the client wanted.
     */
    len = sizeof(struct sockaddr_storage);
    if (getsockname(client_fd, client_to_proxy_sa, &len) < 0) {
        logmsg(LOG_CRIT, "sockgetname client_fd failed: %s", strerror(errno));
        goto fail;
    }
    if (server_lookup(client_sa, client_to_proxy_sa, server_sa, IPPROTO_TCP) != 0) {
        logmsg(LOG_CRIT, "server_lookup failed (no rdr ?)");
        goto fail;
    }
    if (fixed_server) {
        memcpy(server_sa, fixed_server_sa, fixed_server_sa->sa_len);
    }

    /*
     * Setup socket and connect to server.
     */
    if ((server_fd = socket(server_sa->sa_family, SOCK_STREAM,
                    IPPROTO_TCP)) < 0) {
        logmsg(LOG_CRIT, "server socket failed: %s", strerror(errno));
        goto fail;
    }
    if (setnonblock(server_fd) != 0) {
        logmsg(LOG_CRIT, "setnonblock server_fd failed: %s", strerror(errno));
        goto fail;
    }
    if (fixed_proxy && bind(server_fd, sstosa(&fixed_proxy_ss),
                fixed_proxy_ss.ss_len) != 0) {
        logmsg(LOG_CRIT, "fixed server address bind failed: %s", strerror(errno));
        goto fail;
    }
    if (connect(server_fd, server_sa, server_sa->sa_len) < 0 &&
            errno != EINPROGRESS) {
        logmsg(LOG_CRIT, "connect to server %s failed: %s",
                sock_ntop(server_sa), strerror(errno));
        goto fail;
    }
    len = sizeof(struct sockaddr_storage);
    if ((getsockname(server_fd, proxy_to_server_sa, &len)) < 0) {
        logmsg(LOG_CRIT, "getsockname failed: %s",strerror(errno));
        goto fail;
    }   
    
    logmsg(LOG_INFO, "PPTP session started from client %s to server %s through proxy %s",
            sock_ntop(client_sa),
            sock_ntop(server_sa),
            sock_ntop(proxy_to_server_sa));

    /* Keepalive is nice, but don't care if it fails. */
    on = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
        sizeof on);
    setsockopt(server_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
        sizeof on);

    /*
     * Setup buffered events.
     */
    client_bufev = bufferevent_new(client_fd, &client_read,
        &client_write, &client_error, NULL);
    if (client_bufev == NULL) {
        logmsg(LOG_CRIT, "bufferevent_new client failed");
        goto fail;
    }
    bufferevent_settimeout(client_bufev, timeout, 0);
    bufferevent_enable(client_bufev, EV_READ | EV_TIMEOUT);
    
    return;

fail:
    /* TODO(bcarnazzi): write a end_session function */
    exit(1);
}

void
handle_signal(int sig, short event, void *arg)
{
    /*
     * Signal handler rules don't apply, libevent decouples for us.
     */

    logmsg(LOG_ERR, "%s exiting on signal %d", __progname, sig);

    exit_daemon();
}

int
init_session(void)
{
    session_count++;
    return(session_id++);
}

void
logmsg(int pri, const char *message, ...)
{
    va_list ap;

    if (pri > loglevel)
        return;

    va_start(ap, message);

    if (daemonize)
        /* syslog does its own vising. */
        vsyslog(pri, message, ap);
    else {
        char buf[MAX_LOGLINE];
        char visbuf[2 * MAX_LOGLINE];

        /* We don't care about truncation. */
        vsnprintf(buf, sizeof(buf), message, ap);
        strnvis(visbuf, buf, sizeof(visbuf), VIS_CSTYLE | VIS_NL);
        fprintf(stderr, "%s\n", visbuf);
    }

    va_end(ap);
}

int
main(int argc, char *argv[])
{
    struct addrinfo hints, *res;
    struct event ev_conn, ev_sighup, ev_sigint, ev_sigterm;
    struct rlimit rlp;
    int ch, error, listenfd, on;

    /* defaults. */
    daemonize           = 1;
    fixed_proxy         = NULL;
    fixed_server        = NULL;
    fixed_server_port   = PPTP_PORT;
    ipv6_mode           = 0;
    listen_ip           = NULL;
    listen_port         = "2317";
    loglevel            = LOG_NOTICE;
    max_sessions        = 100;
    timeout             = 24 * 3600;

    /* other initialisation. */
    session_count       = 0;
    session_id          = 1;
    
    while ((ch = getopt(argc, argv, "6da:b:D:m:P:p:R:t:")) != -1) {
        switch (ch) {
            case '6':
                ipv6_mode = 1;
                break;
            case 'd':
                daemonize = 0;
                break;
            case 'a':
                fixed_proxy = optarg;
                break;
            case 'b':
                listen_ip = optarg;
                break;
            case 'D':
                loglevel = atoi(optarg);
                if ((loglevel < LOG_EMERG) || (loglevel > LOG_DEBUG))
                    errx(1, "bad loglevel");
                break;
            case 'm':
                max_sessions = atoi(optarg);
                if (max_sessions < 0)
                    errx(1, "bad max sessions");
                break;
            case 'P':
                fixed_server_port = optarg;
                break;
            case 'p':
                listen_port = optarg;
                break;
            case 'R':
                fixed_server = optarg;
                break;
            case 't':
                timeout = atoi(optarg);
                if (timeout < 0)
                    errx(1, "bad timeout");
                break;
            default:
                usage();
                /* NOTREACHED */
        }
    }
    argc -= optind;
    argv += optind;

    if (listen_ip == NULL)
        listen_ip = ipv6_mode ? "::1" : "127.0.0.1";

    /* Check for root to save the user from cryptic failure messages. */
    if (getuid() != 0)
        errx(1, "needs to start as root");

    /* Raise max. open files limit to satisfy max. sessions. */
    rlp.rlim_cur = rlp.rlim_max = (2 * max_sessions) + 10;
    if (setrlimit(RLIMIT_NOFILE, &rlp) == -1)
        err(1, "setrlimit");

    if (fixed_proxy) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = ipv6_mode ? AF_INET6 : AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo(fixed_proxy, NULL, &hints, &res);
        if (error)
            errx(1, "getaddrinfo fixed_proxy failed: %s",
                    gai_strerror(error));
        memcpy(&fixed_proxy_ss, res->ai_addr, res->ai_addrlen);
        logmsg(LOG_INFO, "using %s to connect to server",
                sock_ntop(sstosa(&fixed_proxy_ss)));
        freeaddrinfo(res);
    }

    if (fixed_server) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = ipv6_mode ? AF_INET6 : AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo(fixed_server, fixed_server_port, &hints, &res);
        if (error)
            errx(1, "getaddrinfo fixed_server failed: %s",
                    gai_strerror(error));
        memcpy(&fixed_server_ss, res->ai_addr, res->ai_addrlen);
        logmsg(LOG_INFO, "using fixed server %s port %s",
                sock_ntop(sstosa(&fixed_server_ss)), fixed_server_port);
        freeaddrinfo(res);
    }
    
    /* Setup listener. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    hints.ai_family = ipv6_mode ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(listen_ip, listen_port, &hints, &res);
    if (error)
        errx(1, "getaddrinfo listen address failed: %s",
                gai_strerror(error));
    if ((listenfd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
        err(1, "socket failed");
    on = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
        err(1, "setsockopt SO_REUSEADDR failed");
    if (setnonblock(listenfd) == -1)
        err(1, "setnonblock failed");
    if (bind(listenfd, res->ai_addr, res->ai_addrlen) == -1)
        err(1, "bind failed");
    if (listen(listenfd, TCP_BACKLOG) == -1)
        err(1, "listen failed");
    logmsg(LOG_INFO, "listening on %s port %s", listen_ip, listen_port);
    freeaddrinfo(res);

    /* Initialize pf. */
    init_filter();
    
    if (daemonize) {
        if (daemon(0, 0) == -1)
            err(1, "cannot daemonize");
        openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    tzset();

    if (drop_privs() != 0) {
        logmsg(LOG_ERR, "cannot drop privileges: %s", strerror(errno));
        exit(1);
    }

    event_init();
    
    /* Setup signal handler. */
    signal_set(&ev_sighup, SIGHUP, handle_signal, NULL);
    signal_set(&ev_sigint, SIGINT, handle_signal, NULL);
    signal_set(&ev_sigterm, SIGTERM, handle_signal, NULL);
    signal_add(&ev_sighup, NULL);
    signal_add(&ev_sigint, NULL);
    signal_add(&ev_sigterm, NULL);
    
    event_set(&ev_conn, listenfd, EV_READ | EV_PERSIST, handle_connection, &ev_conn);
    event_add(&ev_conn, NULL);
    
    /* Ignition. */
    event_dispatch();

    logmsg(LOG_ERR, "event_dispatch error: %s", strerror(errno));
    exit_daemon();

    /* NOTREACHED */
    return 1;
}

int
setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return(flags);

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1)
        return(-1);

    return(0);
}

const char *
sock_ntop(struct sockaddr *sa)
{
    static int n = 0;

    /* Cycle to next buffer. */
    n = (n + 1) % NTOP_BUFS;
    ntop_buf[n][0]='\0';

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        return(inet_ntop(AF_INET, &sin->sin_addr, ntop_buf[n], sizeof(ntop_buf[n])));
    }

    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        return(inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buf[n], sizeof(ntop_buf[n])));
    }

    return(NULL);
}

void
usage(void)
{
    fprintf(stderr, "usage: %s [-6d] [-a address] [-b address] [-D level] "
                    "[-m maxsessions]\n                  [-P port] "
                    "[-p port] [-R address] [-t timeout]\n", __progname);
    exit(1);
}

