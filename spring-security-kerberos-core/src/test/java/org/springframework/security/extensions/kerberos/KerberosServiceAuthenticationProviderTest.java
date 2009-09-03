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

package org.springframework.security.extensions.kerberos;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Test class for {@link KerberosServiceAuthenticationProvider}
 * 
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class KerberosServiceAuthenticationProviderTest {
	
	private KerberosServiceAuthenticationProvider provider;
	private KerberosTicketValidator ticketValidator;
	private UserDetailsService userDetailsService;
	
	// data
	private static final byte[] TEST_TOKEN = "TestToken".getBytes();
	private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";
	private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
	private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true,true, AUTHORITY_LIST);
	private static final KerberosServiceRequestToken INPUT_TOKEN = new KerberosServiceRequestToken(TEST_TOKEN);
	
	@Before
	public void before() {
		// mocking
		this.ticketValidator = mock(KerberosTicketValidator.class);
		this.userDetailsService = mock(UserDetailsService.class);
		this.provider = new KerberosServiceAuthenticationProvider();
		this.provider.setTicketValidator(this.ticketValidator);
		this.provider.setUserDetailsService(this.userDetailsService);
	}
	
	@Test
	public void testEverythingWorks() throws Exception {
		// stubbing
		when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TEST_USER);
		when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);
		
		// testing
		Authentication output = provider.authenticate(INPUT_TOKEN);
		assertNotNull(output);
		assertEquals(TEST_USER, output.getName());
		assertEquals(AUTHORITY_LIST, output.getAuthorities());
		assertEquals(USER_DETAILS, output.getPrincipal());	
	}
	
	@Test(expected=UsernameNotFoundException.class)
	public void testUsernameNotFound() throws Exception {
		// stubbing
		when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TEST_USER);
		when(userDetailsService.loadUserByUsername(TEST_USER)).thenThrow(new UsernameNotFoundException(""));
		
		// testing
		provider.authenticate(INPUT_TOKEN);
	}
	
	@Test(expected=BadCredentialsException.class)
	public void testTicketValidationWrong() throws Exception {
		// stubbing
		when(ticketValidator.validateTicket(TEST_TOKEN)).thenThrow(new BadCredentialsException(""));
		
		// testing
		provider.authenticate(INPUT_TOKEN);
	}

}
