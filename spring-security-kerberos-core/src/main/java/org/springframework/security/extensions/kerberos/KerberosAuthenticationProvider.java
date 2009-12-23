/*
 * Copyright 2009 the original author or authors.
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

package org.springframework.security.extensions.kerberos;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class KerberosAuthenticationProvider implements AuthenticationProvider {
    
    private static final Log LOG = LogFactory.getLog(KerberosAuthenticationProvider.class);
    
    private KerberosClient kerberosClient;
    private UserDetailsService userDetailsService;

   

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) authentication;
        String validatedUsername = kerberosClient.login(auth.getName(), auth.getCredentials().toString());
        if (validatedUsername.equalsIgnoreCase(auth.getName()) == false) {
            if (LOG.isDebugEnabled()) {
                LOG.info("Username returned from KDC ("+validatedUsername+") doesn't match with supplied username ("+auth.getName()+")");    
            }
            throw new BadCredentialsException("Username returned from KDC doesn't match with supplied username");
        }
        
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(auth.getName());
        UsernamePasswordAuthenticationToken output = new UsernamePasswordAuthenticationToken(userDetails, auth.getCredentials(), userDetails.getAuthorities());
        return output;
        
    }

    public boolean supports(Class<? extends Object> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    public void setKerberosClient(KerberosClient kerberosClient) {
        this.kerberosClient = kerberosClient;
    }
    
    
    public void setUserDetailsService(UserDetailsService detailsService) {
        this.userDetailsService = detailsService;
    }

}
