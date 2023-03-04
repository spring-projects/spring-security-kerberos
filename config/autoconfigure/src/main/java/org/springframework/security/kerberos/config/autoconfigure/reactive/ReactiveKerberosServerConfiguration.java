/*
 * Copyright 2010-2023 the original author or authors.
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

package org.springframework.security.kerberos.config.autoconfigure.reactive;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

import reactor.core.publisher.Mono;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.config.autoconfigure.KerberosServerConfiguration;
import org.springframework.security.kerberos.webflux.authentication.SpnegoReactiveAuthenticationManager;
import org.springframework.security.kerberos.webflux.authentication.SpnegoServerAuthenticationConverter;
import org.springframework.security.kerberos.webflux.authentication.SpnegoServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;

@Configuration(proxyBeanMethods = false)
@Import(KerberosServerConfiguration.class)
public class ReactiveKerberosServerConfiguration {

	@Bean
	@ConditionalOnBean(KerberosTicketValidator.class)
	SpnegoReactiveAuthenticationManager spnegoReactiveAuthenticationManager(
			KerberosTicketValidator kerberosTicketValidator, Optional<ReactiveUserDetailsService> userDetailsService,
			Optional<UserDetailsChecker> userDetailsChecker) {
		return new SpnegoReactiveAuthenticationManager(kerberosTicketValidator,
				userDetailsService.orElseGet(DefaultUserDetailService::new),
				userDetailsChecker.orElseGet(AccountStatusUserDetailsChecker::new));
	}

	@Bean
	@ConditionalOnBean(SpnegoReactiveAuthenticationManager.class)
	@ConditionalOnMissingBean(SecurityWebFilterChain.class)
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			SpnegoReactiveAuthenticationManager spnegoReactiveAuthenticationManager) {
		AuthenticationWebFilter spnegoAuthenticationWebFilter = new AuthenticationWebFilter(
				spnegoReactiveAuthenticationManager);
		spnegoAuthenticationWebFilter.setServerAuthenticationConverter(new SpnegoServerAuthenticationConverter());
		spnegoAuthenticationWebFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
		return http.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated()).exceptionHandling()
				.authenticationEntryPoint(new SpnegoServerAuthenticationEntryPoint()).and()
				.addFilterAt(spnegoAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION).build();
	}

	private static class DefaultUser implements UserDetails {

		private final String username;

		DefaultUser(String username) {
			this.username = username;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return Collections.emptyList();
		}

		@Override
		public String getPassword() {
			return null;
		}

		@Override
		public String getUsername() {
			return this.username;
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}

	}

	private static class DefaultUserDetailService implements ReactiveUserDetailsService {

		@Override
		public Mono<UserDetails> findByUsername(String username) {
			return Mono.just(new DefaultUser(username));
		}

	}

}
