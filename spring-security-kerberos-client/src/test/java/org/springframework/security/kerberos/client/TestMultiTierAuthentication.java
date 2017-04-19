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
package org.springframework.security.kerberos.client;

import org.junit.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosMultiTier;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.test.KerberosSecurityTestcase;
import org.springframework.security.kerberos.test.MiniKdc;

import java.io.File;

import static org.junit.Assert.*;

/**
 * @author Bogdan Mustiata
 */
public class TestMultiTierAuthentication extends KerberosSecurityTestcase {

    public static final String REALM_NAME = "EXAMPLE.COM";

    public static final String USER_LOGIN_NAME = "user1";
    public static final String USER_FQDN_NAME = "user1@EXAMPLE.COM";
    public static final String USER_PASSWORD = "secret";

    public static final String WEB_TIER_SPN = "HTTP/webtier@EXAMPLE.COM";
    public static final String WEB_TIER_USER_PASSWORD = "secret";

    public static final String SERVICE_TIER_SPN = "HTTP/servicetier@EXAMPLE.COM";
    public static final String SERVICE_TIER_USER_PASSWORD = "secret";

    @Test
    public void testServer() throws Exception {
        MiniKdc kdc = getKdc();
        File workDir = getWorkDir();

        File webTierKeytabFile = new File(workDir, "webtier.keytab");
        kdc.createKeyabFile(webTierKeytabFile, WEB_TIER_SPN, WEB_TIER_USER_PASSWORD);

        File serviceTierKeytabFile = new File(workDir, "servicetier.keytab");
        kdc.createKeyabFile(serviceTierKeytabFile, SERVICE_TIER_SPN, SERVICE_TIER_USER_PASSWORD);

        //
        // User logs in as user1/secret
        //
        KerberosAuthenticationProvider kerberosAuthProvider =
                createUserPassAuthenticator(/* debug: */ true);

        Authentication authentication = kerberosAuthProvider
                .authenticate(new UsernamePasswordAuthenticationToken(USER_LOGIN_NAME, USER_PASSWORD));

        assertEquals(USER_FQDN_NAME, authentication.getName());

        //
        // User creates a ticket for the HTTP/webtier@EXAMPLE.COM, using
        // and then calls the service, using the tokenData
        //
        authentication = KerberosMultiTier.authenticateService(
                authentication, USER_LOGIN_NAME, 3600, WEB_TIER_SPN);

        byte[] tokenData = KerberosMultiTier
                .getTokenForService(authentication, WEB_TIER_SPN);

        assertNotNull(tokenData);
        assertTrue(tokenData.length != 0);

        //
        // The service HTTP/webtier@EXAMPLE.COM authenticates via tokens.
        //
        KerberosServiceAuthenticationProvider webTierAuthenticatorProvider =
                createServiceAuthenticator(
                    true,
                        WEB_TIER_SPN,
                        REALM_NAME,
                    webTierKeytabFile.getCanonicalPath()
                );


        //
        // The service HTTP/webtier@EXAMPLE.COM authenticates the user1@EXAMPLE.COM
        // using the previously stored token, then authenticates itself further as
        // user1@EXAMPLE.COM to the HTTP/servicetier@EXAMPLE.COM.
        //
        Authentication webTierAuthentication = webTierAuthenticatorProvider
                .authenticate(new KerberosServiceRequestToken(tokenData));

        assertEquals(USER_FQDN_NAME, webTierAuthentication.getName());

        webTierAuthentication = KerberosMultiTier.authenticateService(
                webTierAuthentication, USER_FQDN_NAME, 3600, SERVICE_TIER_SPN);

        byte[] workplaceTokenData = KerberosMultiTier.getTokenForService(
                webTierAuthentication, SERVICE_TIER_SPN);

        //
        // The service HTTP/icr@EXAMPLE.COM authenticates via tokens.
        //
        webTierAuthenticatorProvider =
                createServiceAuthenticator(
                        true,
                        SERVICE_TIER_SPN,
                        REALM_NAME,
                        serviceTierKeytabFile.getCanonicalPath()
                );

        //
        // The service HTTP/servicetier@EXAMPLE.COM authenticates via the previously saved
        // token, received from the HTTP/webtier@EXAMPLE.COM on behalf of user1@EXAMPLE.COM
        //
        Authentication serviceTierAuthentication = webTierAuthenticatorProvider
                .authenticate(new KerberosServiceRequestToken(workplaceTokenData));

        assertEquals(USER_FQDN_NAME, serviceTierAuthentication.getName());
    }

    /**
     * Create a username/password authenticator.
     * @return
     */
    private KerberosAuthenticationProvider createUserPassAuthenticator(boolean debug) {
        KerberosAuthenticationProvider kerberosAuthenticationProvider =
                new KerberosAuthenticationProvider();

        SunJaasKerberosClient sunJaasKerberosClient = new SunJaasKerberosClient();

        sunJaasKerberosClient.setDebug(debug);
        sunJaasKerberosClient.setMultiTier(true);

        kerberosAuthenticationProvider.setKerberosClient(sunJaasKerberosClient);
        kerberosAuthenticationProvider.setUserDetailsService(userDetailsService());

        return kerberosAuthenticationProvider;
    }

    private KerberosServiceAuthenticationProvider createServiceAuthenticator(boolean debug,
                                                                             String serviceName,
                                                                             String realmName,
                                                                             String keytabFileLocation) throws Exception {
        KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider =
                new KerberosServiceAuthenticationProvider();

        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setDebug(debug);
        ticketValidator.setServicePrincipal(serviceName);
        ticketValidator.setRealmName(realmName);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabFileLocation));
        ticketValidator.setMultiTier(true);

        ticketValidator.afterPropertiesSet();

        kerberosServiceAuthenticationProvider.setTicketValidator(ticketValidator);
        kerberosServiceAuthenticationProvider.setUserDetailsService(userDetailsService());

        return kerberosServiceAuthenticationProvider;
    }

    private UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return new User(username, "notUsed", true, true, true, true,
                        AuthorityUtils.createAuthorityList("ROLE_USER"));

            }
        };
    }

}
