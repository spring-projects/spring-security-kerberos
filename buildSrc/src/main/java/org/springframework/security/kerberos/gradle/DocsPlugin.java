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

import java.util.HashMap;
import java.util.Map;

import org.antora.gradle.AntoraPlugin;
import org.gradle.api.Action;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.plugins.JavaLibraryPlugin;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.PluginManager;
import org.gradle.api.publish.tasks.GenerateModuleMetadata;

import io.spring.gradle.antora.GenerateAntoraYmlPlugin;
import io.spring.gradle.antora.GenerateAntoraYmlTask;

/**
 * @author Janne Valkealahti
 */
class DocsPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(JavaPlugin.class);
		pluginManager.apply(JavaLibraryPlugin.class);
		pluginManager.apply(ManagementConfigurationPlugin.class);
		pluginManager.apply(SpringMavenPlugin.class);
		pluginManager.apply(AntoraPlugin.class);
		pluginManager.apply(GenerateAntoraYmlPlugin.class);

		ExtractVersionConstraints dependencyVersions = project.getTasks().create("dependencyVersions",
			ExtractVersionConstraints.class, task -> {
				task.enforcedPlatform(":spring-security-kerberos-management");
			});

		configureYmlPlugins(project, dependencyVersions);

		project.getTasks().withType(GenerateModuleMetadata.class, metadata -> {
			metadata.setEnabled(false);
		});
	}

	private void configureYmlPlugins(Project project, ExtractVersionConstraints dependencyVersions) {
		project.getPlugins().withType(GenerateAntoraYmlPlugin.class, (ymlPlugin) -> {
			project.getTasks().withType(GenerateAntoraYmlTask.class, (ymlTask) -> {
				ymlTask.dependsOn(dependencyVersions);
				configureHtmlOnlyAttributes(project, ymlTask, dependencyVersions);
			});
		});
	}

	private void configureHtmlOnlyAttributes(Project project, GenerateAntoraYmlTask ymlTask,
			ExtractVersionConstraints dependencyVersions) {

		ymlTask.doFirst(new Action<Task>() {

			@Override
			public void execute(Task arg0) {
					Map<String, String> versionConstraints = dependencyVersions.getVersionConstraints();
					Map<String, Object> attrs = new HashMap<>();
					attrs.put("version", project.getVersion());
					attrs.put("spring-version", versionConstraints.get("org.springframework:spring-core"));
					attrs.put("spring-security-version", versionConstraints.get("org.springframework.security:spring-security-core"));
					ymlTask.getAsciidocAttributes().putAll(attrs);
			}
		});
	}
}