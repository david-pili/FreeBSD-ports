# Created by: Jean-Yves Lefort <jylefort@FreeBSD.org>
# $FreeBSD$

PORTNAME=	flightgear-mb339-pan
PORTVERSION=	2.1
PORTREVISION=	3
CATEGORIES=	games
MASTER_SITES=	http://hcilab.uniud.it/pan/downloads/
DISTNAME=	mb339pan_${PORTVERSION}

MAINTAINER=	martymac@FreeBSD.org
COMMENT=	Simulation of the MB-339 PAN aerobatic jet

BROKEN_powerpc64=	fails to build: runaway process

RUN_DEPENDS=	${LOCALBASE}/share/flightgear/version:games/flightgear-data

RESTRICTED=	Redistribution prohibited

NO_BUILD=	yes
USES=		zip
WRKSRC=	${WRKDIR}/${PORTNAME}
EXTRACT_AFTER_ARGS=	-d ${WRKSRC}
DATADIR=	${PREFIX}/share/flightgear/Aircraft

PLIST=		${WRKDIR}/pkg-plist
PLIST_DIRS=	%%DATADIR%%

pre-extract:
	@${MKDIR} ${WRKSRC}

pre-install:
	@${RM} ${PLIST}
	@cd ${WRKSRC} && \
	${FIND} * -type d -empty | ${SORT} \
		| ${SED} -e 's|^|@exec ${MKDIR} %D/share/flightgear/Aircraft/|' >> ${PLIST} && \
	${FIND} * -type f | ${SORT} \
		| ${SED} -e 's|^|%%DATADIR%%/|' >> ${PLIST} && \
	${FIND} * -type d -empty | ${SORT} -r \
		| ${SED} -e 's|^|@dir %%DATADIR%%/|' >> ${PLIST}

do-install:
	${MKDIR} ${STAGEDIR}${DATADIR}
	(cd ${WRKSRC}/ && ${COPYTREE_SHARE} . ${STAGEDIR}${DATADIR})

.include <bsd.port.mk>
