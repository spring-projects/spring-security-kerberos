/*
 * Copyright 2009-2015 the original author or authors.
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

package org.springframework.security.kerberos.authentication;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class KerberosTicketValidationTest {

	private String username = "username";

	private Subject subject = new Subject();

	private byte[] responseToken = "token".getBytes();

	private GSSContext gssContext = Mockito.mock(GSSContext.class);

	private GSSCredential delegationCredential = Mockito.mock(GSSCredential.class);

	@Test
	public void createResultOfTicketValidationWithSubject() {

		KerberosTicketValidation ticketValidation = new KerberosTicketValidation(this.username, this.subject,
				this.responseToken, this.gssContext);

		Assertions.assertEquals(this.username, ticketValidation.username());
		Assertions.assertEquals(this.responseToken, ticketValidation.responseToken());
		Assertions.assertEquals(this.gssContext, ticketValidation.getGssContext());

		Assertions.assertNull(ticketValidation.getDelegationCredential(), "With no credential delegation");
	}

	@Test
	public void createResultOfTicketValidationWithSubjectAndDelegation() {

		KerberosTicketValidation ticketValidation = new KerberosTicketValidation(this.username, this.subject,
				this.responseToken, this.gssContext, this.delegationCredential);

		Assertions.assertEquals(this.username, ticketValidation.username());
		Assertions.assertEquals(this.responseToken, ticketValidation.responseToken());
		Assertions.assertEquals(this.gssContext, ticketValidation.getGssContext());

		Assertions.assertEquals(this.delegationCredential, ticketValidation.getDelegationCredential(),
				"With credential delegation");
	}

}
