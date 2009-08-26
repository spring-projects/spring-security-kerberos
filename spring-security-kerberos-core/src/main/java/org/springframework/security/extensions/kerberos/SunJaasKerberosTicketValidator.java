/*
 * Copyright 2002-2008 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.extensions.kerberos;

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;

/**
 * 
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class SunJaasKerberosTicketValidator implements KerberosTicketValidator, InitializingBean {

	private String servicePrincipal;
	private Resource keyTabLocation;
	private Subject serviceSubject;
	private boolean debug = false;

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public String validateTicket(byte[] token) {
		String username = null;
		try {
			username = Subject.doAs(this.serviceSubject, new KerberosValidateAction(token));
		} catch (PrivilegedActionException e) {
			throw new BadCredentialsException("Kerberos validation not succesfull", e);
		}
		return username;
	}

	public void setServicePrincipal(String servicePrincipal) {
		this.servicePrincipal = servicePrincipal;
	}

	public void setKeyTabLocation(Resource keyTabLocation) {
		this.keyTabLocation = keyTabLocation;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.servicePrincipal, "servicePrincipal must be specified");
		Assert.notNull(this.keyTabLocation, "keyTab must be specified");
		LoginConfig loginConfig = new LoginConfig(this.keyTabLocation.getURL().toExternalForm(), this.servicePrincipal,
				this.debug);
		Set<Principal> princ = new HashSet<Principal>(1);
		princ.add(new KerberosPrincipal(this.servicePrincipal));
		Subject sub = new Subject(false, princ, new HashSet<Object>(), new HashSet<Object>());
		LoginContext lc = new LoginContext("", sub, null, loginConfig);
		lc.login();
		this.serviceSubject = lc.getSubject();
	}

	private static class KerberosValidateAction implements PrivilegedExceptionAction<String> {
		byte[] kerberosTicket;

		public KerberosValidateAction(byte[] kerberosTicket) {
			this.kerberosTicket = kerberosTicket;
		}

		@Override
		public String run() throws Exception {
			GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
			context.acceptSecContext(kerberosTicket, 0, kerberosTicket.length);
			String user = context.getSrcName().toString();
			context.dispose();
			return user;
		}

	}

	private static class LoginConfig extends Configuration {
		private String keyTabLocation;
		private String servicePrincipalName;
		private boolean debug;

		public LoginConfig(String keyTabLocation, String servicePrincipalName, boolean debug) {
			this.keyTabLocation = keyTabLocation;
			this.servicePrincipalName = servicePrincipalName;
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

			return new AppConfigurationEntry[] { new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options), };
		}

	}

}
