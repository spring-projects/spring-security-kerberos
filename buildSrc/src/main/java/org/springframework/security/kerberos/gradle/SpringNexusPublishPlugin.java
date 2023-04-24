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

import java.net.URI;
import java.time.Duration;

import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

import io.github.gradlenexus.publishplugin.NexusPublishExtension;
import io.github.gradlenexus.publishplugin.NexusPublishPlugin;
import io.github.gradlenexus.publishplugin.NexusRepository;

public class SpringNexusPublishPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getPlugins().apply(NexusPublishPlugin.class);
		NexusPublishExtension nexusPublishing = project.getExtensions().findByType(NexusPublishExtension.class);
		nexusPublishing.getRepositories().create("ossrh", new Action<NexusRepository>() {
			@Override
			public void execute(NexusRepository nexusRepository) {
				nexusRepository.getNexusUrl().set(URI.create("https://s01.oss.sonatype.org/service/local/"));
				nexusRepository.getSnapshotRepositoryUrl()
						.set(URI.create("https://s01.oss.sonatype.org/content/repositories/snapshots/"));
			}
		});
		nexusPublishing.getConnectTimeout().set(Duration.ofMinutes(3));
		nexusPublishing.getClientTimeout().set(Duration.ofMinutes(3));
	}
}
