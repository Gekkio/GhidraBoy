// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.time.LocalDate
import java.time.format.DateTimeFormatter.BASIC_ISO_DATE
import java.util.Properties

plugins {
    java
    kotlin("jvm") version "2.1.10"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.2"
}

repositories {
    mavenCentral()
}

val ghidraDir =
    (project.findProperty("ghidra.dir") as? String)
        ?: System.getenv("GHIDRA_INSTALL_DIR")
        ?: throw IllegalStateException("Can't find Ghidra installation")

val ghidraProps = Properties().apply { file("$ghidraDir/Ghidra/application.properties").inputStream().use { load(it) } }
val ghidraVersion = ghidraProps.getProperty("application.version")!!
val ghidraRelease = ghidraProps.getProperty("application.release.name")!!

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

tasks.withType<KotlinCompile> {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        optIn.add("kotlin.ExperimentalUnsignedTypes")
    }
}

val ghidraJars =
    fileTree("$ghidraDir/Ghidra/Framework") { include("**/*.jar") } +
        fileTree("$ghidraDir/Ghidra/Features") { include("**/*.jar") }

val sleigh: Configuration by configurations.creating

dependencies {
    compileOnly(ghidraJars)
    sleigh(ghidraJars)

    testImplementation(ghidraJars)
    testImplementation(kotlin("stdlib-jdk8"))
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
}

val generateExtensionProps by tasks.registering {
    val output = layout.buildDirectory.file("generated/extension.properties")
    outputs.file(output)
    doLast {
        file(output).outputStream().use {
            val props = Properties()
            props +=
                mapOf(
                    ("name" to "GhidraBoy"),
                    ("description" to "Support for Sharp SM83 / Game Boy"),
                    ("author" to "Gekkio"),
                    ("createdOn" to LocalDate.now().toString()),
                    ("version" to ghidraVersion),
                )
            props.store(it, null)
        }
    }
}

val compileSleigh by tasks.registering(JavaExec::class) {
    val slaspecFile = file("data/languages/sm83.slaspec")
    val slaFile = file("data/languages/sm83.sla")

    inputs.files(fileTree("data/languages").include("*.slaspec", "*.sinc"))
        .withPropertyName("sourceFiles")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.files(slaFile)
        .withPropertyName("outputFile")

    classpath = sleigh
    mainClass.set("ghidra.pcodeCPort.slgh_compile.SleighCompile")
    args = listOf("-u", "-l", "-n", "-t", "-e", "-c", "-f", slaspecFile.absolutePath)
}

val zip by tasks.registering(Zip::class) {
    archiveFileName.set("ghidra_${ghidraVersion}_${ghidraRelease}_${LocalDate.now().format(BASIC_ISO_DATE)}_${project.name}.zip")

    into("${project.name}/")
    from(tasks.named("jar")) {
        into("lib/")
    }
    from(tasks.named("sourcesJar")) {
        into("lib/")
        rename { "${project.name}-src.zip" }
    }
    from(configurations.runtimeClasspath.get()) {
        into("lib/")
    }

    from(generateExtensionProps)
    from("data") {
        into("data/")
        include("**/*.cspec", "**/*.ldefs", "**/*.pspec", "**/*.sinc", "**/*.slaspec", "**/sleighArgs.txt")
    }
    from("README.markdown", "LICENSE", "Module.manifest")
}

tasks.named("assemble") {
    dependsOn("zip")
}

tasks.named<Test>("test") {
    dependsOn("compileSleigh")
    useJUnitPlatform()

    systemProperty("ghidra.dir", ghidraDir)
    systemProperty("SystemUtilities.isTesting", true)
}

defaultTasks("clean", "assemble")

ktlint {
    setVersion("1.5.0")
}
