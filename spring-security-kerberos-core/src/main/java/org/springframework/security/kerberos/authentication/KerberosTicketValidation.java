package si.fraport.kerberostest.authentication;

import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;

/**
 * Result of ticket validation
 */
public class KerberosTicketValidation {

	private final String username;
	private final Subject subject;
	private final byte[] responseToken;
	private final GSSContext gssContext;

	public KerberosTicketValidation(String username, String servicePrincipal, byte[] responseToken, GSSContext gssContext) {
		final HashSet<KerberosPrincipal> princs = new HashSet<>();
		princs.add(new KerberosPrincipal(servicePrincipal));

		this.username = username;
		this.subject = new Subject(false, princs, new HashSet<>(), new HashSet<>());
		this.responseToken = responseToken;
		this.gssContext = gssContext;
	}


	public KerberosTicketValidation(String username, Subject subject, byte[] responseToken, GSSContext gssContext) {
		this.username = username;
		this.subject = subject;
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
		return this.subject;
	}

}