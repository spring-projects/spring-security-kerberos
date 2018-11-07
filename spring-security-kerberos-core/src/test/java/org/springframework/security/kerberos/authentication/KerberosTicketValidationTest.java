package org.springframework.security.kerberos.authentication;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.junit.Test;

import javax.security.auth.Subject;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

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

        assertNull("With no credential delegation", ticketValidation.getDelegationCredential());
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

        assertEquals("With credential delegation", delegationCredential, ticketValidation.getDelegationCredential());
    }
}