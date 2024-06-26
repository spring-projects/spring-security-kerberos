/*
 * Copyright 2009-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kerberos.authentication;


import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link KerberosServiceAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 */
public class KerberosServiceAuthenticationProviderTest {

    private KerberosServiceAuthenticationProvider provider;
    private KerberosTicketValidator ticketValidator;
    private UserDetailsService userDetailsService;

    // data
    private static final byte[] TEST_TOKEN = "TestToken".getBytes();
    private static final byte[] RESPONSE_TOKEN = "ResponseToken".getBytes();
    private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";

    private static final KerberosTicketValidation TICKET_VALIDATION = new KerberosTicketValidation(TEST_USER, "XXX@test.com", RESPONSE_TOKEN, null);

    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true,true, AUTHORITY_LIST);
    private static final KerberosServiceRequestToken INPUT_TOKEN = new KerberosServiceRequestToken(TEST_TOKEN);

    @BeforeEach
    public void before() {
        System.setProperty("java.security.krb5.conf", "test.com");
        System.setProperty("java.security.krb5.kdc", "kdc.test.com");
        // mocking
        this.ticketValidator = mock(KerberosTicketValidator.class);
        this.userDetailsService = mock(UserDetailsService.class);
        this.provider = new KerberosServiceAuthenticationProvider();
        this.provider.setTicketValidator(this.ticketValidator);
        this.provider.setUserDetailsService(this.userDetailsService);
    }

    @Test
    public void testEverythingWorks() throws Exception {
        Authentication output = callProviderAndReturnUser(USER_DETAILS, INPUT_TOKEN);
        assertNotNull(output);
        assertEquals(TEST_USER, output.getName());
        assertEquals(AUTHORITY_LIST, output.getAuthorities());
        assertEquals(USER_DETAILS, output.getPrincipal());
    }

    @Test
    public void testAuthenticationDetailsPropagation() throws Exception {
    	KerberosServiceRequestToken requestToken = new KerberosServiceRequestToken(TEST_TOKEN);
    	requestToken.setDetails("TestDetails");
        Authentication output = callProviderAndReturnUser(USER_DETAILS, requestToken);
        assertNotNull(output);
        assertEquals(requestToken.getDetails(), output.getDetails());
    }

    @Test
    public void testUserIsDisabled() throws Exception {
        assertThatThrownBy(() -> {
            User disabledUser = new User(TEST_USER, "empty", false, true, true,true, AUTHORITY_LIST);
            callProviderAndReturnUser(disabledUser, INPUT_TOKEN);
        }).isInstanceOf(DisabledException.class);
    }

    @Test
    public void testUserAccountIsExpired() throws Exception {
        assertThatThrownBy(() -> {
            User expiredUser = new User(TEST_USER, "empty", true, false, true,true, AUTHORITY_LIST);
            callProviderAndReturnUser(expiredUser, INPUT_TOKEN);
        }).isInstanceOf(AccountExpiredException.class);
    }

    @Test
    public void testUserCredentialsExpired() throws Exception {
        assertThatThrownBy(() -> {
            User credExpiredUser = new User(TEST_USER, "empty", true, true, false ,true, AUTHORITY_LIST);
            callProviderAndReturnUser(credExpiredUser, INPUT_TOKEN);
        }).isInstanceOf(CredentialsExpiredException.class);
    }

    @Test
    public void testUserAccountLockedCredentialsExpired() throws Exception {
        assertThatThrownBy(() -> {
            User lockedUser = new User(TEST_USER, "empty", true, true, true ,false, AUTHORITY_LIST);
            callProviderAndReturnUser(lockedUser, INPUT_TOKEN);
        }).isInstanceOf(LockedException.class);
    }

    @Test
    public void testUsernameNotFound() throws Exception {
        // stubbing
        when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
        when(userDetailsService.loadUserByUsername(TEST_USER)).thenThrow(new UsernameNotFoundException(""));

        // testing
        assertThatThrownBy(() -> {
            provider.authenticate(INPUT_TOKEN);
        }).isInstanceOf(UsernameNotFoundException.class);
    }


    @Test
    public void testTicketValidationWrong() throws Exception {
        // stubbing
        when(ticketValidator.validateTicket(TEST_TOKEN)).thenThrow(new BadCredentialsException(""));

        // testing
        assertThatThrownBy(() -> {
            provider.authenticate(INPUT_TOKEN);
        }).isInstanceOf(BadCredentialsException.class);
    }

    private Authentication callProviderAndReturnUser(UserDetails userDetails, Authentication inputToken) {
        // stubbing
        when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(userDetails);

        // testing
        return provider.authenticate(inputToken);
    }

}
