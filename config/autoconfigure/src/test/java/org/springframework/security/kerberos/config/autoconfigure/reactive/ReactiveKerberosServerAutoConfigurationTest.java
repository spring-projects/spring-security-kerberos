/*
 * Copyright 2010-2015 the original author or authors.
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

import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.reactive.WebFluxAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.kerberos.config.autoconfigure.KerberosServerProperties;
import org.springframework.security.kerberos.webflux.authentication.SpnegoReactiveAuthenticationManager;

import static org.assertj.core.api.Assertions.assertThat;

class ReactiveKerberosServerAutoConfigurationTest {

	private final ReactiveWebApplicationContextRunner contextRunner = new ReactiveWebApplicationContextRunner()
			.withConfiguration(
					AutoConfigurations.of(WebFluxAutoConfiguration.class, ReactiveSecurityAutoConfiguration.class));

	@Test
	void backOffIfReactiveOAuth2ResourceServerAutoConfigurationPresent() {
		this.contextRunner.withUserConfiguration(TestKerberosConfiguration.class)
				.withConfiguration(AutoConfigurations.of(ReactiveKerberosServerConfiguration.class))
				.withPropertyValues("spring.security.kerberos.server.enabled=true",
						"spring.security.kerberos.server.service-principal=test",
						"spring.security.kerberos.server.keytab-location=file:///tmp/test")
				.run((context) -> assertThat(context).hasSingleBean(SpnegoReactiveAuthenticationManager.class));
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFluxSecurity
	@EnableConfigurationProperties(KerberosServerProperties.class)
	static class TestKerberosConfiguration {

	}

}
