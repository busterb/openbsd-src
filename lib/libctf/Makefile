#	$OpenBSD$

LIB=	ctf

HDRS=	ctf.h

SRCS=	ctf_open.c ctf_subr.c ctf_types.c ctf_func.c ctf_enum.c ctf_member.c \
	ctf_format.c

CFLAGS+=	-I${.CURDIR}

LDADD+=		-lelf -lz
DPADD+=		${LIBELF} ${LIBZ}

includes:
	@cd ${.CURDIR}; for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/$$i || \
		${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
		-m 444 $$i ${DESTDIR}/usr/include"; \
	    echo $$j; \
	    eval "$$j"; \
	done

.include <bsd.lib.mk>
