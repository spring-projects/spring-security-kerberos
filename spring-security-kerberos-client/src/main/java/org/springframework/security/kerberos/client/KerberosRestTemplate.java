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
package org.springframework.security.kerberos.client;

import java.net.URI;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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
import org.springframework.util.StringUtils;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * {@code RestTemplate} that is able to make kerberos SPNEGO authenticated REST
 * requests. Under a hood this {@code KerberosRestTemplate} is using {@link HttpClient} to
 * support Kerberos.
 *
 * <p>Generally this template can be configured in few different ways.
 * <ul>
 *   <li>Leave keyTabLocation and userPrincipal empty if you want to use cached ticket</li>
 *   <li>Use keyTabLocation and userPrincipal if you want to use keytab file</li>
 *   <li>Use loginOptions if you want to customise Krb5LoginModule options</li>
 *   <li>Use a customised httpClient</li>
 * </ul>
 *
 * @author Janne Valkealahti
 *
 */
public class KerberosRestTemplate extends RestTemplate {

	private static final Credentials credentials = new NullCredentials();

	private final String keyTabLocation;
	private final String userPrincipal;
	private final Map<String, Object> loginOptions;

	/**
	 * Instantiates a new kerberos rest template.
	 */
	public KerberosRestTemplate() {
		this(null, null, null, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(HttpClient httpClient) {
		this(null, null, null, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 */
	public KerberosRestTemplate(String keyTabLocation, String userPrincipal) {
		this(keyTabLocation, userPrincipal, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(String keyTabLocation, String userPrincipal, HttpClient httpClient) {
		this(keyTabLocation, userPrincipal, null, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param loginOptions the login options
	 */
	public KerberosRestTemplate(Map<String, Object> loginOptions) {
		this(null, null, loginOptions, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param loginOptions the login options
	 * @param httpClient the http client
	 */
	public KerberosRestTemplate(Map<String, Object> loginOptions, HttpClient httpClient) {
		this(null, null, loginOptions, httpClient);
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param loginOptions the login options
	 */
	public KerberosRestTemplate(String keyTabLocation, String userPrincipal, Map<String, Object> loginOptions) {
		this(keyTabLocation, userPrincipal, loginOptions, buildHttpClient());
	}

	/**
	 * Instantiates a new kerberos rest template.
	 *
	 * @param keyTabLocation the key tab location
	 * @param userPrincipal the user principal
	 * @param loginOptions the login options
	 * @param httpClient the http client
	 */
	private KerberosRestTemplate(String keyTabLocation, String userPrincipal, Map<String, Object> loginOptions, HttpClient httpClient) {
		super(new HttpComponentsClientHttpRequestFactory(httpClient));
		this.keyTabLocation = keyTabLocation;
		this.userPrincipal = userPrincipal;
		this.loginOptions = loginOptions;
	}

	/**
	 * Builds the default instance of {@link HttpClient} having kerberos
	 * support.
	 *
	 * @return the http client with spneno auth scheme
	 */
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
			ClientLoginConfig loginConfig = new ClientLoginConfig(keyTabLocation, userPrincipal, loginOptions);
			Set<Principal> princ;
			if (userPrincipal != null) {
				princ = new HashSet<Principal>(1);
                            	princ.add(new KerberosPrincipal(userPrincipal));
            		}
			else {
				princ = Collections.<Principal>emptySet();
			}
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
		private final String userPrincipal;
		private final Map<String, Object> loginOptions;

		public ClientLoginConfig(String keyTabLocation, String userPrincipal, Map<String, Object> loginOptions) {
			super();
			this.keyTabLocation = keyTabLocation;
			this.userPrincipal = userPrincipal;
			this.loginOptions = loginOptions;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

			Map<String, Object> options = new HashMap<String, Object>();

			// if we don't have keytab or principal only option is to rely on
			// credentials cache.
			if (!StringUtils.hasText(keyTabLocation) || !StringUtils.hasText(userPrincipal)) {
				// cache
				options.put("useTicketCache", "true");
			} else {
				// keytab
				options.put("useKeyTab", "true");
				options.put("keyTab", this.keyTabLocation);
				options.put("principal", this.userPrincipal);
				options.put("storeKey", "true");
			}
			options.put("doNotPrompt", "true");
			options.put("isInitiator", "true");

			if (loginOptions != null) {
				options.putAll(loginOptions);
			}

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
