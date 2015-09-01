#		$Id: Makefile,v 1.3 2006/10/16 18:14:32 bcarnazzi Exp $

LOCALBASE?= /usr/local

PROG=	pptp-proxy
SRCS=	pptp-proxy.c filter.c
MAN=	pptp-proxy.8

CFLAGS+= -I${.CURDIR}
CFLAGS+= -Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
         -Wno-uninitialized
LDADD+=	-levent

MANDIR=${LOCALBASE}/man/cat
BINDIR=${LOCALBASE}/sbin

.include <bsd.prog.mk>
