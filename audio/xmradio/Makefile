# Created by: Thomas Runge <runge@rostock.zgdv.de>
# $FreeBSD$

PORTNAME=	xmradio
PORTVERSION=	1.2
PORTREVISION=	3
CATEGORIES=	audio
MASTER_SITES=	http://BSDforge.com/projects/source/audio/xmradio/

MAINTAINER=	portmaster@BSDforge.com
COMMENT=	Motif based FM tuner (for use with bktr(4) driver)

LICENSE=	BSD2CLAUSE

ONLY_FOR_ARCHS=	i386 amd64

USES=		imake motif xorg
USE_XORG=	ice sm x11 xext xmu xpm xt

PLIST_FILES=	bin/xmradio lib/X11/app-defaults/XMradio

.include <bsd.port.mk>
