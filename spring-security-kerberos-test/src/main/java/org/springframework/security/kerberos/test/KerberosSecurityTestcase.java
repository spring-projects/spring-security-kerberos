/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kerberos.test;

import org.junit.After;
import org.junit.Before;

import java.io.File;
import java.util.Properties;

/**
 * KerberosSecurityTestcase provides a base class for using MiniKdc with other
 * testcases. KerberosSecurityTestcase starts the MiniKdc (@Before) before
 * running tests, and stop the MiniKdc (@After) after the testcases, using
 * default settings (working dir and kdc configurations).
 *
 * @author Original Hadoop MiniKdc Authors
 * @author Janne Valkealahti
 *
 */
public class KerberosSecurityTestcase {
	private MiniKdc kdc;
	private File workDir;
	private Properties conf;

	@Before
	public void startMiniKdc() throws Exception {
		createTestDir();
		createMiniKdcConf();

		kdc = new MiniKdc(conf, workDir);
		kdc.start();
	}

	/**
	 * Create a working directory, it should be the build directory. Under this
	 * directory an ApacheDS working directory will be created, this directory
	 * will be deleted when the MiniKdc stops.
	 */
	public void createTestDir() {
		workDir = new File(System.getProperty("test.dir", "target"));
	}

	/**
	 * Create a Kdc configuration
	 */
	public void createMiniKdcConf() {
		conf = MiniKdc.createConf();
	}

	@After
	public void stopMiniKdc() {
		if (kdc != null) {
			kdc.stop();
		}
	}

	public MiniKdc getKdc() {
		return kdc;
	}

	public File getWorkDir() {
		return workDir;
	}

	public Properties getConf() {
		return conf;
	}

}
