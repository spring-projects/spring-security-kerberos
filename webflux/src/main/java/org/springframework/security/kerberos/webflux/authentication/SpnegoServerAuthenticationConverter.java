/*
 * Copyright 2009-2023 the original author or authors.
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

package org.springframework.security.kerberos.webflux.authentication;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.Base64Utils;
import org.springframework.web.server.ServerWebExchange;

public class SpnegoServerAuthenticationConverter implements ServerAuthenticationConverter {

	private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^Negotiate (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return Optional.ofNullable(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
				.flatMap(this::getTicket).map(KerberosServiceRequestToken::new).map(setDetailsFrom(exchange))
				.orElse(Mono.empty());
	}

	private static Function<KerberosServiceRequestToken, Mono<Authentication>> setDetailsFrom(
			ServerWebExchange exchange) {
		return (kerberosServiceRequestToken) -> {
			String remoteAddress = Optional.ofNullable(exchange.getRequest().getRemoteAddress())
					.map(InetSocketAddress::getHostName).orElse(null);

			return exchange.getSession()
					.map((webSession) -> new WebAuthenticationDetails(remoteAddress, webSession.getId()))
					.map((webAuthenticationDetails) -> {
						kerberosServiceRequestToken.setDetails(webAuthenticationDetails);
						return (Authentication) kerberosServiceRequestToken;
					});
		};
	}

	private Optional<byte[]> getTicket(String authHeader) {
		Matcher matcher = AUTHORIZATION_PATTERN.matcher(authHeader);
		return matcher.matches() ? Optional.ofNullable(matcher.group("token")).map(Base64Utils::decodeFromString)
				: Optional.empty();
	}

}
