--- /home/davidp/Desktop/client_side_request.cc	2017-08-19 12:48:49.000000000 -0600
+++ client_side_request.cc	2019-12-19 13:10:48.943836528 -0700
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
+ * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
  *
  * Squid software is distributed under GPLv2+ license and includes
  * contributions from numerous individuals and organizations.
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
@@ -561,7 +561,6 @@
     debugs(85, DBG_IMPORTANT, "SECURITY ALERT: on URL: " << urlCanonical(http->request));
 
     // IP address validation for Host: failed. reject the connection.
-    http->getConn()->quitAfterError(http->request);
     clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
     clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
     assert (repContext);
@@ -1419,6 +1418,11 @@
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
