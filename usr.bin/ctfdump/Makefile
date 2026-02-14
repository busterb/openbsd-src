
PROG=		ctfdump
SRCS=		ctfdump.c

CFLAGS+=	-W -Wall -Wstrict-prototypes -Wno-unused -Wunused-variable
CFLAGS+=	-I${.CURDIR}/../../lib/libctf

LDADD+=		-lctf -lelf -lz
DPADD+=		${LIBCTF} ${LIBELF} ${LIBZ}

.include <bsd.prog.mk>
