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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.InetAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.DispatcherServletAutoConfiguration;
import org.springframework.boot.autoconfigure.web.EmbeddedServletContainerAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ErrorMvcAutoConfiguration;
import org.springframework.boot.autoconfigure.web.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration;
import org.springframework.boot.context.embedded.EmbeddedServletContainerInitializedEvent;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.kerberos.client.KerberosRestTemplate;
import org.springframework.security.kerberos.test.KerberosSecurityTestcase;
import org.springframework.security.kerberos.test.MiniKdc;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

public class KerberosRestTemplateTests extends KerberosSecurityTestcase {

	private ConfigurableApplicationContext context;

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
		context = null;
	}

    @Test
    public void testSpnego() throws Exception {

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();
		String host = InetAddress.getLocalHost().getCanonicalHostName();

		String serverPrincipal = "HTTP/" + host;
		File serverKeytab = new File(workDir, "server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);

		String clientPrincipal = "client/" + host;
		File clientKeytab = new File(workDir, "client.keytab");
		kdc.createPrincipal(clientKeytab, clientPrincipal);


		context = SpringApplication.run(new Object[] { WebSecurityConfig.class, VanillaWebConfiguration.class,
				WebConfiguration.class }, new String[] { "--security.basic.enabled=true",
				"--security.user.name=username", "--security.user.password=password",
				"--serverPrincipal=" + serverPrincipal, "--serverKeytab=" + serverKeytab.getAbsolutePath() });

		PortInitListener portInitListener = context.getBean(PortInitListener.class);
		assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
		int port = portInitListener.port;

		KerberosRestTemplate restTemplate = new KerberosRestTemplate(clientKeytab.getAbsolutePath(), clientPrincipal);

		String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
		assertThat(response, is("home"));
    }

    @Test
    public void testSpnegoWithForward() throws Exception {

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();
		String host = InetAddress.getLocalHost().getCanonicalHostName();

		String serverPrincipal = "HTTP/" + host;
		File serverKeytab = new File(workDir, "server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);

		context = SpringApplication.run(new Object[] { WebSecurityConfigSpnegoForward.class, VanillaWebConfiguration.class,
				WebConfiguration.class }, new String[] { "--security.basic.enabled=true",
				"--security.user.name=username", "--security.user.password=password",
				"--serverPrincipal=" + serverPrincipal, "--serverKeytab=" + serverKeytab.getAbsolutePath() });

		PortInitListener portInitListener = context.getBean(PortInitListener.class);
		assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
		int port = portInitListener.port;

		// TODO: should tweak minikdc so that we can use kerberos principals
		//       which are not valid, for now just use plain RestTemplate

		// just checking that we get 401 which we skip and
		// get login page content
		RestTemplate restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory());
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			@Override
			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});

		String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
		assertThat(response, is("login"));
    }

    @Test
    public void testSpnegoWithSuccessHandler() throws Exception {

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();
		String host = InetAddress.getLocalHost().getCanonicalHostName();

		String serverPrincipal = "HTTP/" + host;
		File serverKeytab = new File(workDir, "server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);

		String clientPrincipal = "client/" + host;
		File clientKeytab = new File(workDir, "client.keytab");
		kdc.createPrincipal(clientKeytab, clientPrincipal);


		context = SpringApplication.run(new Object[] { WebSecurityConfigSuccessHandler.class, VanillaWebConfiguration.class,
				WebConfiguration.class }, new String[] { "--security.basic.enabled=true",
				"--security.user.name=username", "--security.user.password=password",
				"--serverPrincipal=" + serverPrincipal, "--serverKeytab=" + serverKeytab.getAbsolutePath() });

		PortInitListener portInitListener = context.getBean(PortInitListener.class);
		assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
		int port = portInitListener.port;

		KerberosRestTemplate restTemplate = new KerberosRestTemplate(clientKeytab.getAbsolutePath(), clientPrincipal);

		String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
		assertThat(response, is("home"));
    }

	protected static class PortInitListener implements ApplicationListener<EmbeddedServletContainerInitializedEvent> {

		public int port;
		public CountDownLatch latch = new CountDownLatch(1);

		@Override
		public void onApplicationEvent(EmbeddedServletContainerInitializedEvent event) {
			port = event.getEmbeddedServletContainer().getPort();
			latch.countDown();
		}

	}

    @Configuration
    protected static class VanillaWebConfiguration {

    	@Bean
    	public PortInitListener portListener() {
    		return new PortInitListener();
    	}

    	@Bean
    	public TomcatEmbeddedServletContainerFactory tomcatEmbeddedServletContainerFactory() {
    	    TomcatEmbeddedServletContainerFactory factory = new TomcatEmbeddedServletContainerFactory();
    	    factory.setPort(0);
    	    return factory;
    	}
    }

    @MinimalWebConfiguration
    @Import(SecurityAutoConfiguration.class)
    @Controller
	protected static class WebConfiguration {

    	@RequestMapping(method = RequestMethod.GET)
    	@ResponseBody
    	public String home() {
    		return "home";
    	}

    	@RequestMapping(method = RequestMethod.GET, value = "/login")
    	@ResponseBody
    	public String login() {
    		return "login";
    	}

	}

    @Configuration
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @Import({ EmbeddedServletContainerAutoConfiguration.class,
                    ServerPropertiesAutoConfiguration.class,
                    DispatcherServletAutoConfiguration.class, WebMvcAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class,
                    ErrorMvcAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class })
    protected static @interface MinimalWebConfiguration {
    }

}
