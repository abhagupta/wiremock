package com.github.tomakehurst.wiremock.jetty9;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/**
 * Created by agupt13 on 6/9/16.
 */
public class SslContextFactory extends org.eclipse.jetty.util.ssl.SslContextFactory {

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
