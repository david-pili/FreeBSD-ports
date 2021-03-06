--- src/core/tsi/ssl_transport_security.cc.orig	2018-09-24 23:51:30 UTC
+++ src/core/tsi/ssl_transport_security.cc
@@ -21,7 +21,7 @@
 #include "src/core/tsi/grpc_shadow_boringssl.h"
 
 #include "src/core/tsi/ssl_transport_security.h"
-
+#include <sys/socket.h>
 #include <limits.h>
 #include <string.h>
 
@@ -61,11 +61,10 @@ extern "C" {
 #define TSI_SSL_MAX_PROTECTED_FRAME_SIZE_LOWER_BOUND 1024
 #define TSI_SSL_HANDSHAKER_OUTGOING_BUFFER_INITIAL_SIZE 1024
 
-/* Putting a macro like this and littering the source file with #if is really
-   bad practice.
-   TODO(jboeuf): refactor all the #if / #endif in a separate module. */
-#ifndef TSI_OPENSSL_ALPN_SUPPORT
+#if OPENSSL_VERSION_NUMBER >= 0x10002000L
 #define TSI_OPENSSL_ALPN_SUPPORT 1
+#else
+#define TSI_OPENSSL_ALPN_SUPPORT 0
 #endif
 
 /* TODO(jboeuf): I have not found a way to get this number dynamically from the
@@ -1676,7 +1675,7 @@ tsi_result tsi_create_ssl_client_handshaker_factory_wi
                                   options->cipher_suites);
     if (result != TSI_OK) break;
 
-#if OPENSSL_VERSION_NUMBER >= 0x10100000
+#if OPENSSL_VERSION_NUMBER >= 0x10100000 && !(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
     // X509_STORE_up_ref is only available since OpenSSL 1.1.
     if (options->root_store != nullptr) {
       X509_STORE_up_ref(options->root_store->store);
