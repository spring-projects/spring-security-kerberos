/*
 * Copyright 2009-2015 the original author or authors.
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

package org.springframework.security.kerberos.web;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Test class for {@link SpnegoEntryPoint}
 *
 * @author Mike Wiesner
 * @author Janne Valkealahti
 * @author Andre Schaefer, Namics AG
 * @since 1.0
 */
public class SpnegoEntryPointTest {

	private SpnegoEntryPoint entryPoint = new SpnegoEntryPoint();

	@Test
	public void testEntryPointOk() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		this.entryPoint.commence(request, response, null);

		verify(response).addHeader("WWW-Authenticate", "Negotiate");
		verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void testEntryPointOkWithDispatcher() throws Exception {
		SpnegoEntryPoint entryPoint = new SpnegoEntryPoint();
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		RequestDispatcher requestDispatcher = mock(RequestDispatcher.class);
		lenient().when(request.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
		entryPoint.commence(request, response, null);
		verify(response).addHeader("WWW-Authenticate", "Negotiate");
		verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void testEntryPointForwardOk() throws Exception {
		String forwardUrl = "/login";
		SpnegoEntryPoint entryPoint = new SpnegoEntryPoint(forwardUrl);
		HttpServletResponse response = mock(HttpServletResponse.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		RequestDispatcher requestDispatcher = mock(RequestDispatcher.class);
		lenient().when(request.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
		entryPoint.commence(request, response, null);
		verify(response).addHeader("WWW-Authenticate", "Negotiate");
		verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		verify(request).getRequestDispatcher(forwardUrl);
		verify(requestDispatcher).forward(request, response);
	}

	@Test
	public void testEntryPointForwardAbsolute() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> new SpnegoEntryPoint("http://test/login"));
	}

}
