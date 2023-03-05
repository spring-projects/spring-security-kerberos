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

import java.util.Optional;

import reactor.core.publisher.Mono;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.config.autoconfigure.KerberosServerDefaultConfiguration;
import org.springframework.security.kerberos.webflux.authentication.SpnegoReactiveAuthenticationManager;
import org.springframework.security.kerberos.webflux.authentication.SpnegoServerAuthenticationConverter;
import org.springframework.security.kerberos.webflux.authentication.SpnegoServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;

@Configuration(proxyBeanMethods = false)
@Import(KerberosServerDefaultConfiguration.class)
@EnableWebFluxSecurity
public class ReactiveKerberosServerConfiguration {

	private static final ReactiveUserDetailsService DEFAULT_USER_DETAIL_SERVICE = (username) -> Mono
			.just(new KerberosServerDefaultConfiguration.DefaultUser(username));

	@Bean
	@ConditionalOnBean(KerberosTicketValidator.class)
	SpnegoReactiveAuthenticationManager spnegoReactiveAuthenticationManager(
			KerberosTicketValidator kerberosTicketValidator, Optional<ReactiveUserDetailsService> userDetailsService,
			Optional<UserDetailsChecker> userDetailsChecker) {
		return new SpnegoReactiveAuthenticationManager(kerberosTicketValidator,
				userDetailsService.orElse(DEFAULT_USER_DETAIL_SERVICE),
				userDetailsChecker.orElseGet(AccountStatusUserDetailsChecker::new));
	}

	@Bean
	@ConditionalOnBean(SpnegoReactiveAuthenticationManager.class)
	@ConditionalOnMissingBean(SecurityWebFilterChain.class)
	SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			SpnegoReactiveAuthenticationManager spnegoReactiveAuthenticationManager,
			Optional<Customizer<ServerHttpSecurity.AuthorizeExchangeSpec>> optionalCustomizer) {
		AuthenticationWebFilter spnegoAuthenticationWebFilter = new AuthenticationWebFilter(
				spnegoReactiveAuthenticationManager);
		spnegoAuthenticationWebFilter.setServerAuthenticationConverter(new SpnegoServerAuthenticationConverter());
		spnegoAuthenticationWebFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
		return http.authorizeExchange(optionalCustomizer.orElse((exchanges) -> exchanges.anyExchange().authenticated()))
				.exceptionHandling().authenticationEntryPoint(new SpnegoServerAuthenticationEntryPoint())
				.and()
				.addFilterAt(spnegoAuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION).build();
	}

}
