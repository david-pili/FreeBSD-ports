# $FreeBSD$

PORTNAME=	xxhash
PORTVERSION=	1.4.1
CATEGORIES=	devel
MASTER_SITES=	CHEESESHOP
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	sunpoet@FreeBSD.org
COMMENT=	Python bindings for the xxHash library

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

LIB_DEPENDS=	libxxhash.so:devel/xxhash

USES=		localbase python
USE_PYTHON=	autoplist concurrent distutils

CONFIGURE_ENV=	XXHASH_LINK_SO=yes
MAKE_ENV=	XXHASH_LINK_SO=yes
USE_LOCALE=	en_US.UTF-8

post-install:
	${STRIP_CMD} ${STAGEDIR}${PYTHON_SITELIBDIR}/xxhash/_xxhash.so

.include <bsd.port.mk>
