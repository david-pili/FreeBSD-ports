# $FreeBSD$

PORTNAME=	cliqz
DISTVERSION=	1.29.0
CATEGORIES=	www
MASTER_SITES=	https://s3.amazonaws.com/cdn.cliqz.com/browser-f/APT/:amazon \
		http://repository.cliqz.com/dist/${CLIQZ_CHANNEL}/${DISTVERSION}/${CLIQZ_LAST_BUILD_ID}/:cliqz
DISTFILES=	adult-domains.bin:amazon \
		cliqz@cliqz.com.xpi:cliqz \
		gdprtool@cliqz.com.xpi:cliqz \
		https-everywhere@cliqz.com.xpi:cliqz
DIST_SUBDIR=	${PORTNAME}
EXTRACT_ONLY=	${DISTNAME}${_GITHUB_EXTRACT_SUFX}

MAINTAINER=	fox@FreeBSD.org
COMMENT=	Secure browser (Mozilla based) with built-in quick search

LICENSE=	MPL20
LICENSE_FILE=	${WRKSRC}/LICENSE

FETCH_DEPENDS=	ca_root_nss>=0:security/ca_root_nss
LIB_DEPENDS=	libdbus-1.so:devel/dbus \
		libdbus-glib-1.so:devel/dbus-glib \
		libfontconfig.so:x11-fonts/fontconfig \
		libfreetype.so:print/freetype2 \
		libnspr4.so:devel/nspr \
		libnssutil3.so:security/nss \
		libplc4.so:devel/nspr \
		libplds4.so:devel/nspr

BUILD_DEPENDS=	${LOCALBASE}/include/pulse/pulseaudio.h:audio/pulseaudio \
		${LOCALBASE}/libdata/pkgconfig/xt.pc:x11-toolkits/libXt \
		${PYTHON_PKGNAMEPREFIX}sqlite3>0:databases/py-sqlite3@${PY_FLAVOR} \
		${RUST_DEFAULT}>=1.28:lang/${RUST_DEFAULT} \
		autoconf-2.13:devel/autoconf213 \
		bash:shells/bash \
		graphite2>=1.3.12:graphics/graphite2 \
		harfbuzz>=1.8.8:print/harfbuzz \
		icu>=59.1,1:devel/icu \
		libevent>=2.1.8:devel/libevent \
		libvorbis>=1.3.6,3:audio/libvorbis \
		libvpx>=1.5.0:multimedia/libvpx \
		llvm${LLVM_DEFAULT}>=0:devel/llvm${LLVM_DEFAULT} \
		nasm:devel/nasm \
		node:www/node \
		nspr>=4.19:devel/nspr \
		nss>=3.39:security/nss \
		png>=1.6.34:graphics/png \
		rust-cbindgen>=0.6.2:devel/rust-cbindgen \
		sqlite3>=3.24.0:databases/sqlite3 \
		v4l_compat>0:multimedia/v4l_compat \
		yasm:devel/yasm \
		zip:archivers/zip

USES=		compiler:c11 desktop-file-utils gmake gnome pkgconfig \
		python:2.7,build shebangfix tar:xz xorg

USE_GNOME=	cairo gconf2 gdkpixbuf2 gtk20 gtk30

USE_XORG=	x11 xcb xcb xcomposite xcursor xdamage xext xfixes xi xrender \
		xt

USE_GITHUB=	yes
GH_ACCOUNT=	cliqz-oss
GH_PROJECT=	browser-f

USE_LDCONFIG=	yes

bash_OLD_CMD=	"/bin/bash"
bash_CMD=	${LOCALBASE}/bin/bash
SHEBANG_FILES=	magic_build_and_package.sh

CLIQZ_CHANNEL=		release
# If the DISTVERSION is updated, make sure to update the last build id from
# fetch -qo - https://repository.cliqz.com/dist/${CLIQZ_CHANNEL}/${DISTVERSION}/lastbuildid
CLIQZ_LAST_BUILD_ID=	20190920100917
CLIQZ_ICON=		${PORTNAME}.png
CLIQZ_ICON_SRC=		${WRKSRC}/mozilla-release/browser/branding/${PORTNAME}/default48.png
MOZ_DESKTOP=		${WRKSRC}/mozilla-release/toolkit/mozapps/installer/linux/rpm/mozilla.desktop
CLIQZ_DESKTOP=		${WRKSRC}/mozilla-release/toolkit/mozapps/installer/linux/rpm/cliqz.desktop

MAKE_ENV+=	CQZ_BUILD_ID=${CLIQZ_LAST_BUILD_ID} \
		CQZ_RELEASE_CHANNEL=${CLIQZ_CHANNEL} \
		LLVM_CONFIG=llvm-config${LLVM_DEFAULT} \
		LLVM_OBJDUMP=${LOCALBASE}/llvm${LLVM_DEFAULT}/bin/llvm-objdump \
		MOZBUILD_STATE_PATH=${WRKDIR}

# Configure args passed into mach build system
MOZ_CONFIGURE_ARGS+=	"ac_add_options --disable-crashreporter" \
			"ac_add_options --disable-debug" \
			"ac_add_options --disable-debug-symbols" \
			"ac_add_options --disable-tests" \
			"ac_add_options --disable-updater" \
			"ac_add_options --libclang-path=${LOCALBASE}/llvm${LLVM_DEFAULT}/lib"

.include <bsd.port.pre.mk>

# Default to llvm 8 for i386
.if ${ARCH} == i386 && ${LLVM_DEFAULT:S,-devel,990,} >= 90
LLVM_DEFAULT=	80
.endif

# Require newer Clang than what's in base system unless user opted out
.if ${CC} == cc && ${CXX} == c++ && exists(/usr/lib/libc++.so)
CPP=		${LOCALBASE}/bin/clang-cpp${LLVM_DEFAULT}
CC=		${LOCALBASE}/bin/clang${LLVM_DEFAULT}
CXX=		${LOCALBASE}/bin/clang++${LLVM_DEFAULT}
# XXX avoid warnings
USES:=		${USES:Ncompiler\:*}
.endif

post-extract:
	${CP} ${DISTDIR}/${DIST_SUBDIR}/adult-domains.bin ${WRKSRC}
	${MKDIR} ${WRKSRC}/obj/dist/bin/browser/features
	${CP} ${DISTDIR}/${DIST_SUBDIR}/cliqz@cliqz.com.xpi \
		${DISTDIR}/${DIST_SUBDIR}/https-everywhere@cliqz.com.xpi \
		${DISTDIR}/${DIST_SUBDIR}/gdprtool@cliqz.com.xpi \
		${WRKSRC}/obj/dist/bin/browser/features

post-patch:
	@${CP} ${MOZ_DESKTOP} ${CLIQZ_DESKTOP}
	@${REINPLACE_CMD} -e 's/@MOZ_APP_DISPLAYNAME@/Cliqz Internet/g' \
		-e 's/@MOZ_APP_NAME@/${PORTNAME}/g' \
		-e '/Icon=${PORTNAME}/ s/${PORTNAME}/${CLIQZ_ICON}/' \
		-e '/StartupWMClass/d' \
		${CLIQZ_DESKTOP}
.for MOZ_CONFIGURE_ARG in ${MOZ_CONFIGURE_ARGS}
	@${ECHO_CMD} ${MOZ_CONFIGURE_ARG} >> \
		${WRKSRC}/mozilla-release/browser/config/cliqz.mozconfig;
.endfor
# This prevents linker exhausting memory in i386 builds
.if ${ARCH} == "i386"
	@${ECHO_CMD} 'export LDFLAGS="-Wl,--no-keep-memory -Wl,--as-needed"' >> \
		${WRKSRC}/mozilla-release/browser/config/cliqz.mozconfig
.endif

do-build:
	(cd ${WRKSRC} && ${SETENV} ${MAKE_ENV} ./magic_build_and_package.sh)

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/lib/${PORTNAME}
	(cd ${WRKSRC}/obj/dist/${PORTNAME} && \
		${COPYTREE_SHARE} . ${STAGEDIR}${PREFIX}/lib/${PORTNAME})
	@${CHMOD} 755 ${STAGEDIR}${PREFIX}/lib/${PORTNAME}/${PORTNAME}-bin
	@${CHMOD} 755 ${STAGEDIR}${PREFIX}/lib/${PORTNAME}/${PORTNAME}

post-install:
	${RLN} ${STAGEDIR}${PREFIX}/lib/${PORTNAME}/${PORTNAME}-bin ${STAGEDIR}${PREFIX}/bin/${PORTNAME}
	${INSTALL_DATA} ${CLIQZ_DESKTOP} ${STAGEDIR}${PREFIX}/share/applications/
	${MKDIR} ${STAGEDIR}${PREFIX}/share/pixmaps
	@${CP} ${CLIQZ_ICON_SRC} ${STAGEDIR}${PREFIX}/share/pixmaps/${CLIQZ_ICON}

.include <bsd.port.post.mk>
