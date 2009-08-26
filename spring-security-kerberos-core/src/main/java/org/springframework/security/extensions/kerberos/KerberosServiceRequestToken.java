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

import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

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

	public KerberosServiceRequestToken(Object principal, List<GrantedAuthority> authorities, byte[] token) {
		super(authorities);
		this.token = token;
		this.principal = principal;
		super.setAuthenticated(true);
	}

	private static final long serialVersionUID = 395488921064775014L;
	private final byte[] token;
	private final Object principal;

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
		this.principal = null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(token);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		KerberosServiceRequestToken other = (KerberosServiceRequestToken) obj;
		if (!Arrays.equals(token, other.token))
			return false;
		return true;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	public byte[] getToken() {
		return this.token;
	}

}
