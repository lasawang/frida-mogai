"use strict";

// ssl_pinning.js - 通用 SSL Pinning 绕过
// 覆盖: OkHttp3、HttpsURLConnection、TrustManager、X509TrustManager、Network Security Config

(function () {
  Java.perform(function () {

    // === 1. 通用 TrustManager 绕过 ===
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustAllManager = Java.registerClass({
      name: "com.bypass.TrustAllManager",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () {
          return [];
        }
      }
    });

    // hook SSLContext.init
    SSLContext.init.implementation = function (keyManager, trustManager, secureRandom) {
      this.init(keyManager, [TrustAllManager.$new()], secureRandom);
    };

    // === 2. OkHttp3 CertificatePinner 绕过 ===
    try {
      var CertificatePinner = Java.use("okhttp3.CertificatePinner");
      CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
        return;
      };
      // 兼容旧版 OkHttp
      try {
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, peerCertificates) {
          return;
        };
      } catch (e) {}
    } catch (e) {}

    // === 3. OkHttp3 HostnameVerifier 绕过 ===
    try {
      var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
      OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (hostname, session) {
        return true;
      };
      OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (hostname, certificate) {
        return true;
      };
    } catch (e) {}

    // === 4. HttpsURLConnection 绕过 ===
    try {
      var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
        return;
      };
      HttpsURLConnection.setSSLSocketFactory.implementation = function (factory) {
        return;
      };
    } catch (e) {}

    // === 5. WebViewClient SSL 错误绕过 ===
    try {
      var WebViewClient = Java.use("android.webkit.WebViewClient");
      WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
        handler.proceed();
      };
    } catch (e) {}

    // === 6. Apache HTTP Client (旧版 Android) ===
    try {
      var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
      AbstractVerifier.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean").implementation = function () {
        return;
      };
    } catch (e) {}

    // === 7. Conscrypt / TrustManagerImpl (Android 7+) ===
    try {
      var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        return untrustedChain;
      };
    } catch (e) {}

    // === 8. Flutter/Dart SSL (BoringSSL) ===
    try {
      var boringModule = Process.findModuleByName("libflutter.so");
      if (boringModule) {
        // ssl_crypto_x509_session_verify_cert_chain 返回 1
        var verifyFunc = Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain");
        if (verifyFunc) {
          Interceptor.replace(verifyFunc, new NativeCallback(function () {
            return 1;
          }, "int", []));
        }
      }
    } catch (e) {}
  });
})();
