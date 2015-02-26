/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.extensions.kerberos.client;

import java.net.URI;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * {@code RestTemplate} that is able to make kerberos SPNEGO authenticated REST
 * requests.
 *
 * @author Janne Valkealahti
 *
 */
public class KerberosRestTemplate extends RestTemplate {

	private static final Credentials credentials = new NullCredentials();

	private final String keyTabLocation;
	private final String servicePrincipalName;

	public KerberosRestTemplate(String keyTabLocation, String servicePrincipalName) {
		this(keyTabLocation, servicePrincipalName, buildHttpClient());
	}

	public KerberosRestTemplate(String keyTabLocation, String servicePrincipalName, HttpClient httpClient) {
		super(new HttpComponentsClientHttpRequestFactory(httpClient));
		this.keyTabLocation = keyTabLocation;
		this.servicePrincipalName = servicePrincipalName;
	}

	private static HttpClient buildHttpClient() {
		HttpClientBuilder builder = HttpClientBuilder.create();
		Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider> create()
				.register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true)).build();
		builder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(null, -1, null), credentials);
		builder.setDefaultCredentialsProvider(credentialsProvider);
		CloseableHttpClient httpClient = builder.build();
		return httpClient;
	}

	@Override
	protected final <T> T doExecute(final URI url, final HttpMethod method, final RequestCallback requestCallback,
			final ResponseExtractor<T> responseExtractor) throws RestClientException {

		try {
			ClientLoginConfig loginConfig = new ClientLoginConfig(keyTabLocation, servicePrincipalName, true);
			Set<Principal> princ = new HashSet<Principal>(1);
			princ.add(new KerberosPrincipal(servicePrincipalName));
			Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
			LoginContext lc = new LoginContext("", sub, null, loginConfig);
			lc.login();
			Subject serviceSubject = lc.getSubject();
			return Subject.doAs(serviceSubject, new PrivilegedAction<T>() {

				@Override
				public T run() {
					return KerberosRestTemplate.this.doExecuteSubject(url, method, requestCallback, responseExtractor);
				}
			});

		} catch (Exception e) {
			throw new RestClientException("Error running rest call", e);
		}
	}

	private <T> T doExecuteSubject(URI url, HttpMethod method, RequestCallback requestCallback,
			ResponseExtractor<T> responseExtractor) throws RestClientException {
		return super.doExecute(url, method, requestCallback, responseExtractor);
	}

	private static class ClientLoginConfig extends Configuration {

		private final String keyTabLocation;
		private final String servicePrincipalName;
		private final boolean debug;

		public ClientLoginConfig(String keyTabLocation, String servicePrincipalName, boolean debug) {
			super();
			this.keyTabLocation = keyTabLocation;
			this.servicePrincipalName = servicePrincipalName;
			this.debug = debug;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			HashMap<String, String> options = new HashMap<String, String>();
			options.put("useKeyTab", "true");
			options.put("keyTab", this.keyTabLocation);
			options.put("principal", this.servicePrincipalName);
			options.put("storeKey", "true");
			options.put("doNotPrompt", "true");
			if (this.debug) {
				options.put("debug", "true");
			}
			options.put("isInitiator", "true");

			return new AppConfigurationEntry[] { new AppConfigurationEntry(
					"com.sun.security.auth.module.Krb5LoginModule",
					AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options) };
		}

	}

	private static class NullCredentials implements Credentials {

		@Override
		public Principal getUserPrincipal() {
			return null;
		}

		@Override
		public String getPassword() {
			return null;
		}

	}

}
