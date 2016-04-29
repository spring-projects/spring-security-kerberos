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
package org.springframework.security.kerberos.authentication;

import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;

import javax.security.auth.Subject;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Holds the Subject of the currently authenticated user, since this
 * Jaas object also has the credentials, and permits creating new
 * credentials against other Kerberos services.</p>
 * @author Bogdan Mustiata
 * @see SunJaasKerberosClient
 * @see org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider
 */
public class JaasSubjectHolder {
    private Subject jaasSubject;
    private String username;

    private Map<String, byte[]> savedTokens = new HashMap<String, byte[]>();

    public JaasSubjectHolder(Subject jaasSubject) {
        this.jaasSubject = jaasSubject;
    }

    public JaasSubjectHolder(Subject jaasSubject, String username) {
        this.jaasSubject = jaasSubject;
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public Subject getJaasSubject() {
        return jaasSubject;
    }

    public void addToken(String targetService, byte[] outToken) {
        this.savedTokens.put(targetService, outToken);
    }

    public byte[] getToken(String principalName) {
        return savedTokens.get(principalName);
    }
}
