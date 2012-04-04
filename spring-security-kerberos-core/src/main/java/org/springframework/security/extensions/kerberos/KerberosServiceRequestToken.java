/*
 * Copyright 2009 the original author or authors.
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
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.extensions.kerberos.web.SpnegoAuthenticationProcessingFilter;

/**
 * Holds the Kerberos/SPNEGO token for requesting a kerberized service
 * and is also the output of <code>KerberosServiceAuthenticationProvider</code>.<br>
 * Will mostly be created in <code>SpnegoAuthenticationProcessingFilter</code>
 * and authenticated in <code>KerberosServiceAuthenticationProvider</code>.
 *
 * This token cannot be re-authenticated, as you will get a Kerberos Reply error.
 *
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 * @see KerberosServiceAuthenticationProvider
 * @see SpnegoAuthenticationProcessingFilter
 */

public class KerberosServiceRequestToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 395488921064775014L;
    private final byte[] token;
    private final Object principal;

    /** Creates an authenticated token, normally used as an output of an authentication provider.
     * @param principal the user principal (mostly of instance <code>UserDetails</code>
     * @param authorities the authorities which are granted to the user
     * @param token the Kerberos/SPNEGO token
     * @see UserDetails
     */
    public KerberosServiceRequestToken(Object principal, Collection<? extends GrantedAuthority> authorities, byte[] token) {
        super(authorities);
        this.token = token;
        this.principal = principal;
        super.setAuthenticated(true);
    }

    /**
     * Creates an unauthenticated instance which should then be authenticated by
     * <code>KerberosServiceAuthenticationProvider/code>
     *
     * @param token Kerberos/SPNEGO token
     * @see KerberosServiceAuthenticationProvider
     */
    public KerberosServiceRequestToken(byte[] token) {
        super(null);
        this.token = token;
        this.principal = null;
    }

    /**
     * Calculates hashcode based on the Kerberos token
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(token);
        return result;
    }

    /**
     * equals() is based only on the Kerberos token
     */
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

    /* (non-Javadoc)
     * @see org.springframework.security.core.Authentication#getCredentials()
     */
    @Override
    public Object getCredentials() {
        return null;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.core.Authentication#getPrincipal()
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    /** Returns the Kerberos token
     */
    public byte[] getToken() {
        return this.token;
    }

}
