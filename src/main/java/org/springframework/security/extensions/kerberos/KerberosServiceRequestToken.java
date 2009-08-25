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

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * Holds the Kerberos/SPNEGO token for requesting a kerberized service Will
 * mostly be created in ...Filter and authenticated in
 * KerberosServiceAuthenticationProvider
 * 
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id: $
 */

public class KerberosServiceRequestToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 395488921064775014L;
	private final byte[] token;
	private final Object principal = null;

	/**
	 * Creates an unauthenticated instance which should then be authenticated by
	 * KerberosServiceAuthenticationProvider
	 * 
	 * @param token
	 *            Kerberos/SPNEGO token
	 */
	public KerberosServiceRequestToken(byte[] token) {
		super(null);
		this.token = token;
	}

	@Override
	public Object getCredentials() {
		return this.token;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	public byte[] getToken() {
		return this.token;
	}

}
