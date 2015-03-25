/*
 * Copyright 2009-2015 the original author or authors.
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
package org.springframework.security.kerberos;

import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;
import org.springframework.security.authentication.BadCredentialsException;

/**
 * Implementations of this interface are used in
 * {@link KerberosServiceAuthenticationProvider} to validate a Kerberos/SPNEGO
 * Ticket.
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 * @see KerberosServiceAuthenticationProvider
 */
public interface KerberosTicketValidator {

    /**
     * Validates a Kerberos/SPNEGO ticket.
     *
     * @param token Kerbeos/SPNEGO ticket
     * @return authenticated kerberos principal
     * @throws BadCredentialsException if the ticket is not valid
     */
    public KerberosTicketValidation validateTicket(byte[] token)
            throws BadCredentialsException;

    /**
     * Result of ticket validation
     */
    public static class KerberosTicketValidation {

        private final String username;
        private final byte[] responseToken;
        private final GSSContext gssContext;
        private final String servicePrincipal;

		KerberosTicketValidation(String username, String servicePrincipal, byte[] responseToken, GSSContext gssContext) {
            this.username = username;
            this.servicePrincipal = servicePrincipal;
            this.responseToken = responseToken;
            this.gssContext = gssContext;
        }

        public String username() {
            return username;
        }

        public byte[] responseToken() {
            return responseToken;
        }

        public GSSContext getGssContext() {
            return gssContext;
        }

		public Subject subject() {
			final HashSet<KerberosPrincipal> princs = new HashSet<KerberosPrincipal>();
			princs.add(new KerberosPrincipal(servicePrincipal));
			return new Subject(false, princs, new HashSet<Object>(), new HashSet<Object>());
		}

    }
}
