/*
 * Copyright 2009-2015 the original author or authors.
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

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

import static org.mockito.Mockito.lenient;

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

	private static final KerberosTicketValidation TICKET_VALIDATION = new KerberosTicketValidation(TEST_USER, "XXX",
			RESPONSE_TOKEN, null);

	private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");

	private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true, true,
			AUTHORITY_LIST);

	private static final KerberosServiceRequestToken INPUT_TOKEN = new KerberosServiceRequestToken(TEST_TOKEN);

	@BeforeEach
	public void before() {
		// mocking
		this.ticketValidator = Mockito.mock(KerberosTicketValidator.class);
		this.userDetailsService = Mockito.mock(UserDetailsService.class);
		this.provider = new KerberosServiceAuthenticationProvider();
		this.provider.setTicketValidator(this.ticketValidator);
		this.provider.setUserDetailsService(this.userDetailsService);
	}

	@Test
	public void testEverythingWorks() throws Exception {
		Authentication output = callProviderAndReturnUser(USER_DETAILS, INPUT_TOKEN);
		Assertions.assertNotNull(output);
		Assertions.assertEquals(TEST_USER, output.getName());
		Assertions.assertEquals(AUTHORITY_LIST, output.getAuthorities());
		Assertions.assertEquals(USER_DETAILS, output.getPrincipal());
	}

	@Test
	public void testAuthenticationDetailsPropagation() throws Exception {
		KerberosServiceRequestToken requestToken = new KerberosServiceRequestToken(TEST_TOKEN);
		requestToken.setDetails("TestDetails");
		Authentication output = callProviderAndReturnUser(USER_DETAILS, requestToken);
		Assertions.assertNotNull(output);
		Assertions.assertEquals(requestToken.getDetails(), output.getDetails());
	}

	@Test
	public void testUserIsDisabled() throws Exception {
		Assertions.assertThrows(DisabledException.class, () -> {
			User disabledUser = new User(TEST_USER, "empty", false, true, true, true, AUTHORITY_LIST);
			callProviderAndReturnUser(disabledUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUserAccountIsExpired() throws Exception {
		Assertions.assertThrows(AccountExpiredException.class, () -> {
			User expiredUser = new User(TEST_USER, "empty", true, false, true, true, AUTHORITY_LIST);
			callProviderAndReturnUser(expiredUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUserCredentialsExpired() throws Exception {
		Assertions.assertThrows(CredentialsExpiredException.class, () -> {
			User credExpiredUser = new User(TEST_USER, "empty", true, true, false, true, AUTHORITY_LIST);
			callProviderAndReturnUser(credExpiredUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUserAccountLockedCredentialsExpired() throws Exception {
		Assertions.assertThrows(LockedException.class, () -> {
			User lockedUser = new User(TEST_USER, "empty", true, true, true, false, AUTHORITY_LIST);
			callProviderAndReturnUser(lockedUser, INPUT_TOKEN);
		});
	}

	@Test
	public void testUsernameNotFound() throws Exception {
		Assertions.assertThrows(UsernameNotFoundException.class, () -> {
			// stubbing
			Mockito.when(this.ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
			Mockito.when(this.userDetailsService.loadUserByUsername(TEST_USER))
					.thenThrow(new UsernameNotFoundException(""));

			// testing
			this.provider.authenticate(INPUT_TOKEN);
		});
	}

	@Test
	public void testTicketValidationWrong() {
		Assertions.assertThrows(BadCredentialsException.class, () -> {
			// stubbing
			lenient().when(this.ticketValidator.validateTicket(TEST_TOKEN)).thenThrow(new BadCredentialsException(""));

			// testing
			this.provider.authenticate(INPUT_TOKEN);
		});
	}

	private Authentication callProviderAndReturnUser(UserDetails userDetails, Authentication inputToken) {
		// stubbing
		lenient().when(this.ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
		lenient().when(this.userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(userDetails);

		// testing
		return this.provider.authenticate(inputToken);
	}

}
