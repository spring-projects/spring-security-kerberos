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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.extensions.kerberos.web.SpnegoAuthenticationProcessingFilter;


/**
 * <p>Authentication Provider which validates Kerberos Service Tickets 
 * or SPNEGO Tokens (which includes Kerberos Service Tickets).</p>
 * 
 * <p>It needs a <code>KerberosTicketValidator</code>, which contains the
 * code to validate the ticket, as this code is different between
 * SUN and IBM JRE.<br>
 * It also needs an <code>UserDetailsService</code> to load the user properties
 * and the <code>GrantedAuthorities</code>, as we only get back the username
 * from Kerbeos</p>
 * 
 * You can see an example configuration in <code>SpnegoAuthenticationProcessingFilter</code>.
 * 
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 * @see KerberosTicketValidator
 * @see UserDetailsService
 * @see SpnegoAuthenticationProcessingFilter
 */
public class KerberosServiceAuthenticationProvider implements
		AuthenticationProvider {
	
	private KerberosTicketValidator ticketValidator;
	private UserDetailsService userDetailsService;
	
	
	/** The <code>UserDetailsService</code> to use, for loading the user properties
	 * and the <code>GrantedAuthorities</code>.
	 */
	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	/** The <code>KerberosTicketValidator</code> to use, for validating
	 * the Kerberos/SPNEGO tickets.
	 */
	public void setTicketValidator(KerberosTicketValidator ticketValidator) {
		this.ticketValidator = ticketValidator;
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.core.Authentication)
	 */
	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
		byte[] token = auth.getToken();
		String username = this.ticketValidator.validateTicket(token);
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
		return new KerberosServiceRequestToken(userDetails, userDetails.getAuthorities(), token);
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
	 */
	@Override
	public boolean supports(Class<? extends Object> auth) {
		return KerberosServiceRequestToken.class.isAssignableFrom(auth);
	}

}
