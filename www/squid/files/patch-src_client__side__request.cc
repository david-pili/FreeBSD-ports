http://www.squid-cache.org/Versions/v3/3.5/changesets/SQUID-2018_2.patch

commit 8232b83d3fa47a1399f155cb829db829369fbae9 (refs/remotes/origin/v3.5)
Author: squidadm <squidadm@users.noreply.github.com>
Date:   2018-01-21 08:07:08 +1300

    Fix indirect IP logging for transactions without a client connection (#129) (#136)

--- src/client_side_request.cc.orig	2018-02-23 13:39:32 UTC
+++ src/client_side_request.cc
@@ -488,9 +488,9 @@
         * Ensure that the access log shows the indirect client
         * instead of the direct client.
         */
-        ConnStateData *conn = http->getConn();
-        conn->log_addr = request->indirect_client_addr;
-        http->al->cache.caddr = conn->log_addr;
+        http->al->cache.caddr = request->indirect_client_addr;
+        if (ConnStateData *conn = http->getConn())
+            conn->log_addr = request->indirect_client_addr;
     }
     request->x_forwarded_for_iterator.clean();
     request->flags.done_follow_x_forwarded_for = true;
@@ -540,7 +540,9 @@
 {
     // IP address validation for Host: failed. Admin wants to ignore them.
     // NP: we do not yet handle CONNECT tunnels well, so ignore for them
-    if (!Config.onoff.hostStrictVerify && http->request->method != Http::METHOD_CONNECT) {
+    const Ssl::BumpMode bumpMode = http->getConn()->sslBumpMode;
+    debug(85, 3 "NDTesting Ssl bump mode" << bumpMode);
+    if ((!Config.onoff.hostStrictVerify && http->request->method != Http::METHOD_CONNECT) || (!Config.onoff.hostStrictVerify && (bumpMode == Ssl::bumpPeek || bumpMode == Ssl::bumpSplice)) {
         debugs(85, 3, "SECURITY ALERT: Host header forgery detected on " << http->getConn()->clientConnection <<
                " (" << A << " does not match " << B << ") on URL: " << urlCanonical(http->request));

@@ -1419,6 +1421,11 @@
 bool
 ClientRequestContext::sslBumpAccessCheck()
 {
+    if (!http->getConn()) {
+        http->al->ssl.bumpMode = Ssl::bumpEnd; // SslBump does not apply; log -
+        return false;
+    }
+
     // If SSL connection tunneling or bumping decision has been made, obey it.
     const Ssl::BumpMode bumpMode = http->getConn()->sslBumpMode;
     if (bumpMode != Ssl::bumpEnd) {
