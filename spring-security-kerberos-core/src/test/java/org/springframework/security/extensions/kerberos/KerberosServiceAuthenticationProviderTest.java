/*
 * Copyright 2002-2008 the original author or authors.
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
	private static final byte[] testToken = "TestToken".getBytes();
	private static final String testuser = "Testuser@SPRINGSOURCE.ORG";
	private static final List<GrantedAuthority> authorityList = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
	private static final UserDetails userDetails = new User(testuser, "empty", true, true, true,true, authorityList);
	private static final KerberosServiceRequestToken input = new KerberosServiceRequestToken(testToken);
	
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
		when(ticketValidator.validateTicket(testToken)).thenReturn(testuser);
		when(userDetailsService.loadUserByUsername(testuser)).thenReturn(userDetails);
		
		// testing
		Authentication output = provider.authenticate(input);
		assertNotNull(output);
		assertEquals(testuser, output.getName());
		assertEquals(authorityList, output.getAuthorities());
		assertEquals(userDetails, output.getPrincipal());	
	}
	
	@Test(expected=UsernameNotFoundException.class)
	public void testUsernameNotFound() throws Exception {
		// stubbing
		when(ticketValidator.validateTicket(testToken)).thenReturn(testuser);
		when(userDetailsService.loadUserByUsername(testuser)).thenThrow(new UsernameNotFoundException(""));
		
		// testing
		provider.authenticate(input);
	}
	
	@Test(expected=BadCredentialsException.class)
	public void testTicketValidationWrong() throws Exception {
		// stubbing
		when(ticketValidator.validateTicket(testToken)).thenThrow(new BadCredentialsException(""));
		
		// testing
		provider.authenticate(input);
	}

}
