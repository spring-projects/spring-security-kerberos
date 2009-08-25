package org.springframework.security.extensions.kerberos;

public interface KerberosTicketValidator {

	public abstract String validateTicket(byte[] token);

}