package com.github.tomakehurst.wiremock.jetty9;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

/**
 * Created by agupt13 on 6/10/16.
 */
public class CustomizeSSLSocketFactory extends SSLSocketFactory {

    private SSLSocketFactory defaultFactory;



    // Android 5.0+ (API level21) provides reasonable default settings
    // but it still allows SSLv3
    // https://developer.android.com/about/versions/android-5.0-changes.html#ssl
    static String protocols[] = null;
    static String cipherSuites[] = null;
    static {


        try {
            SSLSocket socket = null;

            socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();

            if (socket != null) {
                /* set reasonable protocol versions */
                // - enable all supported protocols (enables TLSv1.1 and TLSv1.2 on Android <5.0)
                // - remove all SSL versions (especially SSLv3) because they're insecure now
                List<String> protocols = new LinkedList<>();
                for (String protocol : socket.getSupportedProtocols())
                    if (!protocol.toUpperCase().contains("SSL"))
                        protocols.add(protocol);
                System.out.println("Setting allowed TLS protocols: " + protocols);
                CustomizeSSLSocketFactory.protocols = protocols.toArray(new String[protocols.size()]);

                   /* set up reasonable cipher suites */

                // choose known secure cipher suites
                List<String> allowedCiphers = Arrays.asList(
                        // TLS 1.2
                        "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                        "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                        "SSL_DHE_DSS_WITH_DES_CBC_SHA",
                        "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                        "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                        "SSL_DHE_RSA_WITH_DES_CBC_SHA",
                        "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
                        "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
                        "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
                        "SSL_DH_anon_WITH_DES_CBC_SHA",
                        "SSL_DH_anon_WITH_RC4_128_MD5",
                        "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
                        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
                        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                        "SSL_RSA_WITH_DES_CBC_SHA",
                        "SSL_RSA_WITH_NULL_MD5",
                        "SSL_RSA_WITH_NULL_SHA",
                        "SSL_RSA_WITH_RC4_128_MD5",
                        "SSL_RSA_WITH_RC4_128_SHA",
                        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
                        "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
                        "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
                        "TLS_DH_anon_WITH_AES_256_CBC_SHA",
                        "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
                        "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
                        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
                        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
                        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_NULL_SHA",
                        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
                        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
                        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
                        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDH_ECDSA_WITH_NULL_SHA",
                        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                        "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
                        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
                        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
                        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
                        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDH_RSA_WITH_NULL_SHA",
                        "TLS_ECDH_RSA_WITH_RC4_128_SHA",
                        "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
                        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                        "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
                        "TLS_ECDH_anon_WITH_NULL_SHA",
                        "TLS_ECDH_anon_WITH_RC4_128_SHA",
                        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
                        "TLS_FALLBACK_SCSV",
                        "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
                        "TLS_PSK_WITH_AES_128_CBC_SHA",
                        "TLS_PSK_WITH_AES_256_CBC_SHA",
                        "TLS_PSK_WITH_RC4_128_SHA",
                        "TLS_RSA_WITH_AES_128_CBC_SHA",
                        "TLS_RSA_WITH_AES_128_CBC_SHA256",
                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_RSA_WITH_AES_256_CBC_SHA",
                        "TLS_RSA_WITH_AES_256_CBC_SHA256",
                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_RSA_WITH_NULL_SHA256");
                List<String> availableCiphers = Arrays.asList(socket.getSupportedCipherSuites());
                System.out.println("Available cipher suites: " + availableCiphers);
                System.out.println("Cipher suites enabled by default: " + Arrays.asList(socket.getEnabledCipherSuites()));

                // take all allowed ciphers that are available and put them into preferredCiphers
                HashSet<String> preferredCiphers = new HashSet<>(allowedCiphers);
                preferredCiphers.retainAll(availableCiphers);

                    /* For maximum security, preferredCiphers should *replace* enabled ciphers (thus disabling
                     * ciphers which are enabled by default, but have become unsecure), but I guess for
                     * the security level of DAVdroid and maximum compatibility, disabling of insecure
                     * ciphers should be a server-side task */

                // add preferred ciphers to enabled ciphers
                HashSet<String> enabledCiphers = preferredCiphers;
                enabledCiphers.addAll(new HashSet<>(Arrays.asList(socket.getEnabledCipherSuites())));

                System.out.println("Enabling (only) those TLS ciphers: " + enabledCiphers);
                CustomizeSSLSocketFactory.cipherSuites = enabledCiphers.toArray(new String[enabledCiphers.size()]);
            }

        } catch (IOException e) {
            System.err.println("Couldn't determine default TLS settings");
        }
    }

    public CustomizeSSLSocketFactory(){
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            sslContext.init( null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.printf("[CLIENT] chain = %s, authType = %s%n", Arrays.toString(chain), authType);
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.printf("[SERVER] chain = %s, authType = %s%n", Arrays.toString(chain), authType);
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new SecureRandom());

            defaultFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new AssertionError(); // The system has no TLS. Just give up.
        }
    }

    private void upgradeTLS(SSLSocket ssl) {
        // Android 5.0+ (API level21) provides reasonable default settings
        // but it still allows SSLv3
        // https://developer.android.com/about/versions/android-5.0-changes.html#ssl

        if (protocols != null) {
            System.out.println("Setting allowed TLS protocols in upgradeTLS: " +  protocols);
            ssl.setEnabledProtocols(protocols);
        }

        if (cipherSuites != null) {
            System.out.println("Setting allowed TLS ciphers for Android <5 in upgradeTLS: " + protocols);
            ssl.setEnabledCipherSuites(cipherSuites);
        }
    }


    public String[] getDefaultCipherSuites() {
        return cipherSuites;
    }


    public String[] getSupportedCipherSuites() {
        return cipherSuites;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        Socket ssl = defaultFactory.createSocket(s, host, port, autoClose);
        if (ssl instanceof SSLSocket)
            upgradeTLS((SSLSocket)ssl);
        return ssl;
    }

    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        Socket ssl = defaultFactory.createSocket(host, port);
        if (ssl instanceof SSLSocket)
            upgradeTLS((SSLSocket)ssl);
        return ssl;
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        Socket ssl = defaultFactory.createSocket(host, port, localHost, localPort);
        if (ssl instanceof SSLSocket)
            upgradeTLS((SSLSocket)ssl);
        return ssl;
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket ssl = defaultFactory.createSocket(host, port);
        if (ssl instanceof SSLSocket)
            upgradeTLS((SSLSocket)ssl);
        return ssl;
    }

    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket ssl = defaultFactory.createSocket(address, port, localAddress, localPort);
        if (ssl instanceof SSLSocket)
            upgradeTLS((SSLSocket)ssl);
        return ssl;
    }
}
