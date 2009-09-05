/*
 * Copyright 2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.extensions.kerberos.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Sends back a request for a Negotiate Authentication to the browser.
 *
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 * @see SpnegoAuthenticationProcessingFilter
 */
public class SpnegoEntryPoint implements AuthenticationEntryPoint {

    private static final Log LOG = LogFactory.getLog(SpnegoEntryPoint.class);

    /* (non-Javadoc)
     * @see org.springframework.security.web.AuthenticationEntryPoint#commence(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, org.springframework.security.core.AuthenticationException)
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException ex) throws IOException, ServletException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Sending back Negotiate Header for request: "+request.getRequestURL());
        }
        response.addHeader("WWW-Authenticate", "Negotiate");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.flushBuffer();

    }

}
