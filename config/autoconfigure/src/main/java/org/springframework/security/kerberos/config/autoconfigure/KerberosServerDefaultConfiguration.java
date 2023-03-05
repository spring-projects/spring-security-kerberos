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

package org.springframework.security.kerberos.config.autoconfigure;

import java.util.Collection;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;

@Configuration(proxyBeanMethods = false)
public class KerberosServerDefaultConfiguration {

	private final KerberosServerProperties kerberosServerProperties;

	public KerberosServerDefaultConfiguration(KerberosServerProperties kerberosServerProperties) {
		this.kerberosServerProperties = kerberosServerProperties;
	}

	@Bean
	KerberosTicketValidator kerberosTicketValidator() {
		SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator = new SunJaasKerberosTicketValidator();
		sunJaasKerberosTicketValidator.setServicePrincipal(this.kerberosServerProperties.getServicePrincipal());
		sunJaasKerberosTicketValidator.setKeyTabLocation(this.kerberosServerProperties.getKeytabLocation());
		return sunJaasKerberosTicketValidator;
	}

	public static class DefaultUser implements UserDetails {

		private final String username;

		public DefaultUser(String username) {
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

}
