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

package org.springframework.security.kerberos.webflux.authentication;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;

public class SpnegoReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final ReactiveUserDetailsService userDetailsService;

	private final KerberosTicketValidator ticketValidator;

	private final UserDetailsChecker userDetailsChecker;

	public SpnegoReactiveAuthenticationManager(KerberosTicketValidator ticketValidator,
			ReactiveUserDetailsService userDetailsService, UserDetailsChecker userDetailsChecker) {
		this.ticketValidator = ticketValidator;
		this.userDetailsService = userDetailsService;
		this.userDetailsChecker = userDetailsChecker;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		KerberosServiceRequestToken auth = (KerberosServiceRequestToken) authentication;
		byte[] token = auth.getToken();
		return Mono.just(token).map(this.ticketValidator::validateTicket)
				.flatMap((ticketValidation) -> this.userDetailsService.findByUsername(ticketValidation.username())
						.map((userDetails) -> {
							this.userDetailsChecker.check(userDetails);
							this.additionalAuthenticationChecks(userDetails, auth);
							KerberosServiceRequestToken responseAuth = new KerberosServiceRequestToken(userDetails,
									ticketValidation, userDetails.getAuthorities(), token);
							responseAuth.setDetails(authentication.getDetails());
							return responseAuth;
						}));
	}

	protected void additionalAuthenticationChecks(UserDetails userDetails, KerberosServiceRequestToken authentication)
			throws AuthenticationException {
	}

}
