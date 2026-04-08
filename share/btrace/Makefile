#	$OpenBSD: Makefile,v 1.2 2023/05/12 14:34:00 claudio Exp $

FILES=	ifaddrref.bt kalloc.bt kcpuflamegraph.bt kfunctime.bt kprofile.bt \
	netlock.bt opencount.bt runqlat.bt solock.bt syscalllat.bt \
	syscount.bt uprofile.bt uvmcount.bt
SCRIPTS=	bviz bspeedscope bspeedscope-analyze
NOOBJ=	noobj

install:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 444 ${FILES} \
	    ${DESTDIR}${BINDIR}/btrace
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 555 ${SCRIPTS} \
	    ${DESTDIR}${BINDIR}/btrace

.include <bsd.prog.mk>
