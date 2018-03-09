package org.springframework.security.kerberos.authentication;

public interface KerberosAuthentication {

    JaasSubjectHolder getJaasSubjectHolder();
}
