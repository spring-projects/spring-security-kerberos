/*
 * Copyright 2002-2015 the original author or authors.
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

package demo.app;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

public class ActiveDirectoryLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {

	@Override
	public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData,
			String username) {
		String[] groups = userData.getStringAttributes("memberOf");

		if (groups == null) {
			return AuthorityUtils.NO_AUTHORITIES;
		}

		ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(groups.length);

		for (String group : groups) {
			authorities.add(new SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()));
		}

		return authorities;
	}

}
