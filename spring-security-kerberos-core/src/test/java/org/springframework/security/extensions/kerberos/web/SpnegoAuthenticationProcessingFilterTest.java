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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.extensions.kerberos.KerberosServiceRequestToken;

/**
 * Test class for {@link SpnegoAuthenticationProcessingFilter}
 *
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class SpnegoAuthenticationProcessingFilterTest {



    private SpnegoAuthenticationProcessingFilter filter;
    private AuthenticationManager authenticationManager;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    // data
    private static final byte[] TEST_TOKEN = "TestToken".getBytes();
    private static final String TEST_TOKEN_BASE64 = "VGVzdFRva2Vu";
    private static final Authentication AUTHENTICATION = new KerberosServiceRequestToken("test",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"), TEST_TOKEN);
    private static final String HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Negotiate ";


    @Before
    public void before() {
        // mocking
        authenticationManager = mock(AuthenticationManager.class);
        filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
    }

    @Test
    public void testEverythingWorks() throws Exception {
        // stubbing
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX+TEST_TOKEN_BASE64);
        when(authenticationManager.authenticate(new KerberosServiceRequestToken(TEST_TOKEN))).thenReturn(AUTHENTICATION);

        // testing
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        assertEquals(AUTHENTICATION, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testNoHeader() throws Exception {
        filter.doFilter(request, response, chain);
        // If the header is not present, the filter is not allowed to call authenticate()
        verify(authenticationManager, never()).authenticate(any(Authentication.class));
        // chain should go on
        verify(chain).doFilter(request, response);
        assertEquals(null, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testAuthenticationFails() throws Exception {
        // stubbing
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX+TEST_TOKEN_BASE64);
        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));

        // testing
        filter.doFilter(request, response, chain);
        // chain should stop here and it should send back a 500
        // future version should call some error handler
        verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    @After
    public void after() {
        SecurityContextHolder.clearContext();
    }


}
