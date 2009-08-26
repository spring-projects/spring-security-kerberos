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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class KerberosServiceAuthenticationProvider implements
		AuthenticationProvider {
	
	private KerberosTicketValidator ticketValidator;
	private UserDetailsService userDetailsService;
	
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public void setTicketValidator(KerberosTicketValidator ticketValidator) {
		this.ticketValidator = ticketValidator;
	}

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
		byte[] token = auth.getToken();
		String username = this.ticketValidator.validateTicket(token);
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
		return new KerberosServiceRequestToken(userDetails, userDetails.getAuthorities(), token);
	}

	@Override
	public boolean supports(Class<? extends Object> auth) {
		return KerberosServiceRequestToken.class.isAssignableFrom(auth);
	}

}
