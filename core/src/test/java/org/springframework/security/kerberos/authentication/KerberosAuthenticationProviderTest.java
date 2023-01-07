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

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Test class for {@link KerberosAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class KerberosAuthenticationProviderTest {

	private KerberosAuthenticationProvider provider;

	private KerberosClient kerberosClient;

	private UserDetailsService userDetailsService;

	private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";

	private static final String TEST_PASSWORD = "password";

	private static final UsernamePasswordAuthenticationToken INPUT_TOKEN = new UsernamePasswordAuthenticationToken(
			TEST_USER, TEST_PASSWORD);

	private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");

	private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true, true,
			AUTHORITY_LIST);

	private static final JaasSubjectHolder JAAS_SUBJECT_HOLDER = new JaasSubjectHolder(null, TEST_USER);

	@BeforeEach
	public void before() {
		// mocking
		this.kerberosClient = mock(KerberosClient.class);
		this.userDetailsService = mock(UserDetailsService.class);
		this.provider = new KerberosAuthenticationProvider();
		this.provider.setKerberosClient(this.kerberosClient);
		this.provider.setUserDetailsService(this.userDetailsService);
	}

	@Test
	public void testLoginOk() throws Exception {
		lenient().when(this.userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);
		lenient().when(this.kerberosClient.login(TEST_USER, TEST_PASSWORD)).thenReturn(JAAS_SUBJECT_HOLDER);

		Authentication authenticate = this.provider.authenticate(INPUT_TOKEN);

		verify(this.kerberosClient).login(TEST_USER, TEST_PASSWORD);

		Assertions.assertNotNull(authenticate);
		Assertions.assertEquals(TEST_USER, authenticate.getName());
		Assertions.assertEquals(USER_DETAILS, authenticate.getPrincipal());
		Assertions.assertEquals(TEST_PASSWORD, authenticate.getCredentials());
		Assertions.assertEquals(AUTHORITY_LIST, authenticate.getAuthorities());

	}

}
