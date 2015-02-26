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
package org.springframework.security.extensions.kerberos.web;

import static org.mockito.Mockito.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

/**
 * Test class for {@link SpnegoEntryPoint}
 *
 * @author Mike Wiesner
 * @author Janne Valkealahti
 * @since 1.0
 */
public class SpnegoEntryPointTest {

    private SpnegoEntryPoint entryPoint = new SpnegoEntryPoint();

    @Test
    public void testEntryPointOk() throws Exception {
    	HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        entryPoint.commence(request, response, null);

        verify(response).addHeader("WWW-Authenticate", "Negotiate");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

}
