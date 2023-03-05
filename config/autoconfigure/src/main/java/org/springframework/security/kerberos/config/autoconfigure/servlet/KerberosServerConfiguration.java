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

package org.springframework.security.kerberos.config.autoconfigure.servlet;

import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.config.autoconfigure.KerberosServerDefaultConfiguration;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration(proxyBeanMethods = false)
@Import(KerberosServerDefaultConfiguration.class)
public class KerberosServerConfiguration {

	private static final UserDetailsService DEFAULT_USER_DETAIL_SERVICE = KerberosServerDefaultConfiguration.DefaultUser::new;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, SpnegoEntryPoint spnegoEntryPoint,
			SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter,
			Optional<Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>> optionalCustomizer) throws Exception {
		http.authorizeHttpRequests(optionalCustomizer.orElse((authorizeHttpRequests) -> authorizeHttpRequests.anyRequest().authenticated()))
				.exceptionHandling().authenticationEntryPoint(spnegoEntryPoint)
				.and()
				.addFilterBefore(spnegoAuthenticationProcessingFilter, BasicAuthenticationFilter.class);
		return http.build();
	}

	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint();
	}

	@Bean
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	@Bean
	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider(
			KerberosTicketValidator ticketValidator, Optional<UserDetailsService> optionalUserDetailsService) {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(ticketValidator);
		provider.setUserDetailsService(optionalUserDetailsService.orElse(DEFAULT_USER_DETAIL_SERVICE));
		return provider;
	}

	@Bean
	public AuthenticationManager authManager(HttpSecurity http,
			KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class)
				.authenticationProvider(kerberosServiceAuthenticationProvider).build();
	}

}
