# Created by: Mark Felder <feld@FreeBSD.org>
# $FreeBSD$

PORTNAME=	librouteros
PORTVERSION=	1.1.2
PORTREVISION=	5
CATEGORIES=	net
MASTER_SITES=	http://verplant.org/librouteros/files/

MAINTAINER=	ports@FreeBSD.org
COMMENT=	Library for communicating with network devices by MikroTik

LICENSE=	GPLv2
LICENSE_FILE=	${WRKSRC}/COPYING

BROKEN=		unfetchable
DEPRECATED=	Unfetchable, unmaintained
EXPIRATION_DATE=	2019-10-16

LIB_DEPENDS=	libgcrypt.so:security/libgcrypt

GNU_CONFIGURE=	yes
INSTALL_TARGET=	install-strip
USES=		libtool tar:bzip2
USE_LDCONFIG=	yes

LDFLAGS+=	-L${LOCALBASE}/lib
CFLAGS+=	-I${LOCALBASE}/include -Wno-error

PORTDOCS=	AUTHORS COPYING ChangeLog INSTALL NEWS README

OPTIONS_DEFINE=	DOCS

post-install:
	${MKDIR} ${STAGEDIR}${DOCSDIR}
	cd ${WRKSRC} && ${INSTALL_DATA} ${PORTDOCS} ${STAGEDIR}${DOCSDIR}

.include <bsd.port.mk>
