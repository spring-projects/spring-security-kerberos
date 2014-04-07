package org.springframework.security.extensions.kerberos.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.extensions.kerberos.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Adds a WWW-Authenticate (or other) header to the response following
 * successful authentication.
 * 
 * @author Jeremy.Stone
 */
public class ResponseHeaderSettingKerberosAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private static final String NEGOTIATE_PREFIX = "Negotiate ";

    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    private String headerName = WWW_AUTHENTICATE;

    private String headerPrefix = NEGOTIATE_PREFIX;

    /**
     * Sets the name of the header to set. By default this is
     * {@value #WWW_AUTHENTICATE}.
     * 
     * @param a_headerName
     */
    public void setHeaderName(String a_headerName) {
        headerName = a_headerName;
    }

    /**
     * Sets the value of the prefix for the encoded response token value. By
     * default this is {@value #NEGOTIATE_PREFIX}.
     * 
     * @param a_headerPrefix
     */
    public void setHeaderPrefix(String a_headerPrefix) {
        headerPrefix = a_headerPrefix;
    }

    /**
     * @see org.springframework.security.web.authentication.AuthenticationSuccessHandler#onAuthenticationSuccess(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse,
     * org.springframework.security.core.Authentication)
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;

        if (auth.hasResponseToken()) {
            response.addHeader(headerName,
                    headerPrefix + auth.getEncodedResponseToken());
        }
    }
}
