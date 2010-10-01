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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.extensions.kerberos.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

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
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;

    // data
    private static final byte[] TEST_TOKEN = "TestToken".getBytes();
    private static final String TEST_TOKEN_BASE64 = "VGVzdFRva2Vu";
    private static final Authentication AUTHENTICATION = new KerberosServiceRequestToken("test",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"), TEST_TOKEN);
    private static final String HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "Negotiate ";
    private static final BadCredentialsException BCE = new BadCredentialsException("");

    @Before
    public void before() throws Exception {
        // mocking
        authenticationManager = mock(AuthenticationManager.class);
        filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        filter.afterPropertiesSet();
    }

    @Test
    public void testEverythingWorks() throws Exception {
        everythingWorks();
    }

    @Test
    public void testEverythingWorksWithHandlers() throws Exception {
        createHandler();
        everythingWorks();
        verify(successHandler).onAuthenticationSuccess(request, response, AUTHENTICATION);
        verify(failureHandler, never()).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(AuthenticationException.class));
    }

    private void everythingWorks() throws IOException, ServletException {
        // stubbing
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX + TEST_TOKEN_BASE64);
        when(authenticationManager.authenticate(new KerberosServiceRequestToken(TEST_TOKEN))).thenReturn(AUTHENTICATION);

        // testing
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        assertEquals(AUTHENTICATION, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testNoHeader() throws Exception {
        filter.doFilter(request, response, chain);
        // If the header is not present, the filter is not allowed to call
        // authenticate()
        verify(authenticationManager, never()).authenticate(any(Authentication.class));
        // chain should go on
        verify(chain).doFilter(request, response);
        assertEquals(null, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testAuthenticationFails() throws Exception {
        authenticationFails();
        verify(response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    @Test
    public void testAuthenticationFailsWithHandlers() throws Exception {
        createHandler();
        authenticationFails();
        verify(failureHandler).onAuthenticationFailure(request, response, BCE);
        verify(successHandler, never()).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(Authentication.class));
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    public void testAlreadyAuthenticated() throws Exception {
        try {
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            SecurityContextHolder.getContext().setAuthentication(existingAuth);
            when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX + TEST_TOKEN_BASE64);
            filter.doFilter(request, response, chain);
            verify(authenticationManager, never()).authenticate(any(Authentication.class));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    public void testAlreadyAuthenticatedWithNotAuthenticatedToken() throws Exception {
        try {
            // this token is not authenticated yet!
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike");
            SecurityContextHolder.getContext().setAuthentication(existingAuth);
            everythingWorks();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    public void testAlreadyAuthenticatedWithAnonymousToken() throws Exception {
        try {
            Authentication existingAuth = new AnonymousAuthenticationToken("test", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            SecurityContextHolder.getContext().setAuthentication(existingAuth);
            everythingWorks();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
    
    @Test
    public void testAlreadyAuthenticatedNotActive() throws Exception {
        try {
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            SecurityContextHolder.getContext().setAuthentication(existingAuth);
            filter.setSkipIfAlreadyAuthenticated(false);
            everythingWorks();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void authenticationFails() throws IOException, ServletException {
        // stubbing
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX + TEST_TOKEN_BASE64);
        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(BCE);

        // testing
        filter.doFilter(request, response, chain);
        // chain should stop here and it should send back a 500
        // future version should call some error handler
        verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    }

    private void createHandler() {
        successHandler = mock(AuthenticationSuccessHandler.class);
        failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setSuccessHandler(successHandler);
        filter.setFailureHandler(failureHandler);
    }

    @After
    public void after() {
        SecurityContextHolder.clearContext();
    }

}
