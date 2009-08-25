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
