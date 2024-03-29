/*
 * Copyright 2023 the original author or authors.
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
package org.springframework.security.kerberos.gradle;

import org.gradle.api.Project;

/**
 * @author Janne Valkealahti
 */
class Utils {

	static boolean isSnapshot(Project project) {
		String projectVersion = projectVersion(project);
		return projectVersion.matches("^.*([.-]BUILD)?-SNAPSHOT$");
	}

	static boolean isMilestone(Project project) {
		String projectVersion = projectVersion(project);
		return projectVersion.matches("^.*[.-]M\\d+$") || projectVersion.matches("^.*[.-]RC\\d+$");
	}

	static boolean isRelease(Project project) {
		return !(isSnapshot(project) || isMilestone(project));
	}

	private static String projectVersion(Project project) {
		return String.valueOf(project.getVersion());
	}
}
