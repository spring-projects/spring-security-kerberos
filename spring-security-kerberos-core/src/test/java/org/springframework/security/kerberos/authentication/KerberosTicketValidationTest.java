package org.springframework.security.kerberos.authentication;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
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

        assertThat(ticketValidation.username()).isEqualTo(username);
        assertThat(ticketValidation.responseToken()).isEqualTo(responseToken);
        assertThat(ticketValidation.getGssContext()).isEqualTo(gssContext);

        assertThat(ticketValidation.getDelegationCredential()).as("With no credential delegation").isNull();
    }

    @Test
    public void createResultOfTicketValidationWithSubjectAndDelegation() {

        KerberosTicketValidation ticketValidation = new KerberosTicketValidation(
                username,
                subject,
                responseToken,
                gssContext,
                delegationCredential);

        assertThat(ticketValidation.username()).isEqualTo(username);
        assertThat(ticketValidation.responseToken()).isEqualTo(responseToken);
        assertThat(ticketValidation.getGssContext()).isEqualTo(gssContext);

        assertThat(ticketValidation.getDelegationCredential()).as("With credential delegation").isEqualTo(delegationCredential);
    }
}