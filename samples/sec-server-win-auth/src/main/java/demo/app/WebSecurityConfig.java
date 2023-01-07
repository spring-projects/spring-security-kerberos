/*
 * Copyright 2002-2015 the original author or authors.
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

package demo.app;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Value("${app.ad-domain}")
	private String adDomain;

	@Value("${app.ad-server}")
	private String adServer;

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.ldap-search-base}")
	private String ldapSearchBase;

	@Value("${app.ldap-search-filter}")
	private String ldapSearchFilter;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, SpnegoEntryPoint spnegoEntryPoint,
			SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter) throws Exception {
		http.exceptionHandling().authenticationEntryPoint(spnegoEntryPoint).and().authorizeRequests()
				.antMatchers("/", "/home").permitAll().anyRequest().authenticated().and().formLogin()
				.loginPage("/login").permitAll().and().logout().permitAll().and()
				.addFilterBefore(spnegoAuthenticationProcessingFilter, BasicAuthenticationFilter.class);
		return http.build();
	}

	@Bean
	public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
		return new ActiveDirectoryLdapAuthenticationProvider(this.adDomain, this.adServer);
	}

	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/login");
	}

	@Bean
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	@Bean
	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() throws Exception {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(sunJaasKerberosTicketValidator());
		provider.setUserDetailsService(ldapUserDetailsService());
		return provider;
	}

	@Bean
	public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
		SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
		ticketValidator.setServicePrincipal(this.servicePrincipal);
		ticketValidator.setKeyTabLocation(new FileSystemResource(this.keytabLocation));
		ticketValidator.setDebug(true);
		return ticketValidator;
	}

	@Bean
	public KerberosLdapContextSource kerberosLdapContextSource() throws Exception {
		KerberosLdapContextSource contextSource = new KerberosLdapContextSource(this.adServer);
		contextSource.setLoginConfig(loginConfig());
		return contextSource;
	}

	public SunJaasKrb5LoginConfig loginConfig() throws Exception {
		SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
		loginConfig.setKeyTabLocation(new FileSystemResource(this.keytabLocation));
		loginConfig.setServicePrincipal(this.servicePrincipal);
		loginConfig.setDebug(true);
		loginConfig.setIsInitiator(true);
		loginConfig.afterPropertiesSet();
		return loginConfig;
	}

	@Bean
	public LdapUserDetailsService ldapUserDetailsService() throws Exception {
		FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(this.ldapSearchBase, this.ldapSearchFilter,
				this.kerberosLdapContextSource());
		LdapUserDetailsService service = new LdapUserDetailsService(userSearch,
				new ActiveDirectoryLdapAuthoritiesPopulator());
		service.setUserDetailsMapper(new LdapUserDetailsMapper());
		return service;
	}

	@Bean
	public AuthenticationManager authManager(HttpSecurity http,
			ActiveDirectoryLdapAuthenticationProvider authenticationProvider,
			KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class).authenticationProvider(authenticationProvider)
				.authenticationProvider(kerberosServiceAuthenticationProvider).build();
	}

}
