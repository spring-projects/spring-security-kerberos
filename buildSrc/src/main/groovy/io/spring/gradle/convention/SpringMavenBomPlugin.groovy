package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlatformPlugin
import org.springframework.gradle.properties.SpringCopyPropertiesPlugin
import org.springframework.gradle.SpringMavenPlugin

public class SpringMavenBomPlugin implements Plugin<Project> {
	static String MAVEN_BOM_TASK_NAME = "mavenBom"

	public void apply(Project project) {
		project.plugins.apply(JavaPlatformPlugin)
		project.plugins.apply(SpringMavenPlugin)
		project.plugins.apply(SpringCopyPropertiesPlugin)
	}
}
