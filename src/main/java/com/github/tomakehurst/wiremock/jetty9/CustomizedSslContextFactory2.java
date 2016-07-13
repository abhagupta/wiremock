package com.github.tomakehurst.wiremock.jetty9;


import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public class CustomizedSslContextFactory2 extends org.eclipse.jetty.util.ssl.SslContextFactory {

    SSLContext context;
    SSLSocketFactory factory;
    String type;

    public CustomizedSslContextFactory2() {
        try {
            System.out.println("CALLING CUSTOM CONTEXT FACTORY 2");
            init();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    void init() throws KeyManagementException, NoSuchAlgorithmException {
        System.out.println("INSIDE INIT");
        context = SSLContext.getInstance("TLS");
                //type = Cube.from("SSL", "TLS").random());
        context.init(null, new TrustManager[]{new X509TrustManager() {
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

        factory = context.getSocketFactory();
    }

    public String[] getDefaultCipherSuites()
    {
        System.out.println("getDefaultCipherSuites method");
        String[] array = new String[getCipherSuites().size()];
        return getCipherSuites().toArray(array);
    }

    public String[] getSupportedCipherSuites() {
        String[] array = new String[getCipherSuites().size()];
        return getCipherSuites().toArray(array);
    }

    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return configCipherSuites(factory.createSocket(s, host, port, autoClose));
    }

    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return configCipherSuites(factory.createSocket(host, port));
    }

    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        return configCipherSuites(factory.createSocket(host, port, localHost, localPort));
    }

    public Socket createSocket(InetAddress host, int port) throws IOException {
        return configCipherSuites(factory.createSocket(host, port));
    }

    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return configCipherSuites(factory.createSocket(address, port, localAddress, localPort));
    }

    List<String> getCipherSuites() {
         List<String> allowedCiphers = Arrays.asList("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
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

        return allowedCiphers;

    }

    Socket configCipherSuites(Socket socket) {
        if (!(socket instanceof SSLSocket)) return socket;
        SSLSocket sslsocket = (SSLSocket) socket;
        HashSet<String> suites = new HashSet<>(getCipherSuites());
        while (suites.size() > 0) {
            try {
                sslsocket.setEnabledCipherSuites(suites.toArray(new String[suites.size()]));
                break;
            } catch (Throwable e) {
                String message = e.getMessage();
                for (String cipher : suites) {
                    if (message.toLowerCase().contains(cipher.toLowerCase())) {
                        suites.remove(cipher);
                        System.out.printf("Cipher suite %s has been removed.%n", cipher);
                        break;
                    }
                }
            }
        }
        return socket;
    }

    public void customize(SSLEngine sslEngine)
    {
        SSLParameters sslParams = sslEngine.getSSLParameters();
        // sslParams.setEndpointIdentificationAlgorithm(_endpointIdentificationAlgorithm);
        sslEngine.setSSLParameters(sslParams);

        if (super.getWantClientAuth())
            sslEngine.setWantClientAuth(super.getWantClientAuth());
        if (super.getNeedClientAuth())
            sslEngine.setNeedClientAuth(super.getNeedClientAuth());

        sslEngine.setEnabledCipherSuites(super.selectCipherSuites(
                sslEngine.getEnabledCipherSuites(),
                sslEngine.getSupportedCipherSuites()));

        sslEngine.setEnabledProtocols(super.selectProtocols(sslEngine.getEnabledProtocols(),sslEngine.getSupportedProtocols()));
    }
}