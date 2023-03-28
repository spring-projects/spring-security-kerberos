/*
 * Copyright 2023 the original author or authors.
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
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.kerberos.client.KerberosRestTemplate;

@SpringBootApplication
@EnableAutoConfiguration(exclude = SecurityAutoConfiguration.class)
public class Application implements CommandLineRunner {

	@Value("${app.user-principal}")
	private String userPrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.access-url}")
	private String accessUrl;

	@Override
	public void run(String... args) throws Exception {
		KerberosRestTemplate restTemplate =
				new KerberosRestTemplate(keytabLocation, userPrincipal);
		String response = restTemplate.getForObject(accessUrl, String.class);
		System.out.println(response);
	}

    public static void main(String[] args) throws Throwable {
		new SpringApplicationBuilder(Application.class).web(WebApplicationType.NONE).run(args);
    }
}
