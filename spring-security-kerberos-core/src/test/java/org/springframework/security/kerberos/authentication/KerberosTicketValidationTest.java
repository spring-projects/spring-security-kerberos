package org.springframework.security.kerberos.authentication;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

public class KerberosTicketValidationTest {

    private String username = "username";
    private Subject subject = new Subject();
    private byte[] responseToken = "token".getBytes();
    private GSSContext gssContext = mock(GSSContext.class);
    private GSSCredential delegationCredential = mock(GSSCredential.class);

    @Test
    public void createResultOfTicketValidationWithSubject() {

        KerberosTicketValidation ticketValidation = new KerberosTicketValidation(
                username,
                subject,
                responseToken,
                gssContext);

        assertEquals(username, ticketValidation.username());
        assertEquals(responseToken, ticketValidation.responseToken());
        assertEquals(gssContext, ticketValidation.getGssContext());

        assertNull(ticketValidation.getDelegationCredential(), "With no credential delegation");
    }

    @Test
    public void createResultOfTicketValidationWithSubjectAndDelegation() {

        KerberosTicketValidation ticketValidation = new KerberosTicketValidation(
                username,
                subject,
                responseToken,
                gssContext,
                delegationCredential);

        assertEquals(username, ticketValidation.username());
        assertEquals(responseToken, ticketValidation.responseToken());
        assertEquals(gssContext, ticketValidation.getGssContext());

        assertEquals(delegationCredential, ticketValidation.getDelegationCredential(), "With credential delegation");
    }
}