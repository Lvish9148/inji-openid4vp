plugins {
    alias(libs.plugins.android.library)
    kotlin("multiplatform")
    alias(libs.plugins.dokka)
    `maven-publish`
    alias(libs.plugins.sonarqube)
    signing
    jacoco
    alias(libs.plugins.kotlin.serialization)
}

jacoco {
    toolVersion = "0.8.11"
    reportsDirectory = layout.buildDirectory.dir("reports/jacoco")
}

kotlin {
    jvmToolchain(17)

    androidTarget()

    jvm {
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.jetbrains.kotlinx.serialization.json)
                implementation(libs.okhttp3)
                implementation(libs.commons.codec)
                implementation(libs.jackson.module.kotlin)
                implementation(libs.jackson.databind)
                implementation(libs.jackson.core)
                implementation(libs.jackson.annotations)
                implementation(libs.nimbus.jose.jwt)
                implementation(libs.bouncyCastle)
                implementation(libs.identity.credential)
                implementation(libs.ld.signatures.java)
                implementation(libs.data.integrity.java.get().toString()) {
                    exclude(group = "com.danubetech", module = "key-formats-java")
                }
                implementation("com.danubetech:key-formats-java:1.9.0")
                implementation(libs.jsonld.common.java)
                implementation(libs.vcverifier)
                implementation(libs.bcpkix)
                implementation(libs.google.tink)
                implementation(libs.augustcellars.cose)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.junit)
                implementation(libs.mockk)
                implementation(libs.mockwebserver)
                implementation(libs.androidx.junit)
                implementation(libs.androidx.espresso.core)
                implementation(libs.jupiter.junit)
                implementation(libs.assertj)
            }
        }
        val jvmMain by getting
        val androidMain by getting
        val jvmTest by getting
        val androidUnitTest by getting

    }

}

configurations.configureEach {
    exclude(group = "com.apicatalog", module = "titanium-json-ld-jre8")
}

android {
    namespace = "io.mosip.openid4vp"
    compileSdk = 34

    defaultConfig {
        minSdk = 23
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.withType<AbstractPublishToMaven>().configureEach {
    onlyIf {
        publication.name in listOf("aar", "jarRelease")
    }
}

tasks.register("jacocoMergedReport", JacocoReport::class) {
    dependsOn("jvmTest", "testDebugUnitTest")

    reports {
        xml.required.set(true)
        html.required.set(true)
        xml.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoMergedReport/jacocoMergedReport.xml"))
        html.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/jacocoMergedReport/html"))
    }

    doFirst {
        val tempDir = file("${layout.buildDirectory.get()}/tmp/jacoco-merged")
        tempDir.deleteRecursively()
        tempDir.mkdirs()

        val uniqueClasses = mutableSetOf<String>()
        val classFiles = mutableListOf<File>()

        val jvmDir = file("${layout.buildDirectory.get()}/classes/kotlin/jvm/main")
        if (jvmDir.exists()) {
            jvmDir.walkTopDown()
                .filter { it.isFile && it.name.endsWith(".class") }
                .forEach { classFile ->
                    val relativePath = classFile.relativeTo(jvmDir).path
                    if (uniqueClasses.add(relativePath)) {
                        val targetFile = File(tempDir, relativePath)
                        targetFile.parentFile.mkdirs()
                        classFile.copyTo(targetFile)
                        classFiles.add(targetFile)
                    }
                }
        }


        val androidDir = file("${layout.buildDirectory.get()}/tmp/kotlin-classes/debug")
        if (androidDir.exists()) {
            androidDir.walkTopDown()
                .filter { it.isFile && it.name.endsWith(".class") }
                .forEach { classFile ->
                    val relativePath = classFile.relativeTo(androidDir).path
                    if (uniqueClasses.add(relativePath)) {
                        val targetFile = File(tempDir, relativePath)
                        targetFile.parentFile.mkdirs()
                        classFile.copyTo(targetFile)
                        classFiles.add(targetFile)
                    }
                }
        }
    }

    classDirectories.setFrom(
        fileTree("${layout.buildDirectory.get()}/tmp/jacoco-merged") {
            exclude(
                "**/*Test*.*",
                "**/*\$WhenMappings.*",
                "**/*\$Companion.*",
                "**/R.class",
                "**/R$*.class",
                "**/BuildConfig.*",
                "**/Manifest*.*"
            )
        }
    )

    sourceDirectories.setFrom(files(
        "src/commonMain/kotlin",
        "src/jvmMain/kotlin",
        "src/androidMain/kotlin"
    ))

    executionData.setFrom(files(
        "${layout.buildDirectory.get()}/jacoco/jvmTest.exec",
        "${layout.buildDirectory.get()}/jacoco/testDebugUnitTest.exec"
    ))
}


tasks.withType<Test> {
    jacoco {
        isEnabled = true
    }
    finalizedBy(tasks.named("jacocoMergedReport"))
}

tasks {
    register<Wrapper>("wrapper") {
        group = "build setup"
        description = "Generates the Gradle wrapper files for this project"
        gradleVersion = "8.5"
    }
}

tasks.register("prepareKotlinBuildScriptModel") {
    group = "ide"
    description = "No-op task required by the Kotlin IDE build script model"
}
tasks.register<Jar>("jarRelease") {
    group = "build"
    description = "Assembles the release JAR, including generated Javadoc"
    dependsOn("dokkaJavadoc")
    dependsOn("assembleRelease")
    dependsOn("jvmJar")
}

tasks.register<Jar>("javadocJar") {
    group = "documentation"
    description = "Packages the generated Dokka HTML docs into a javadoc JAR"
    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register("generatePom") {
    group = "publishing"
    description = "Generates the POM files for the AAR and JAR release publications"
    dependsOn("generatePomFileForAarPublication", "generatePomFileForJarReleasePublication")
}

afterEvaluate {
    val signTasks = listOf("signJarReleasePublication", "signAarPublication")
    val publishTasks = listOf(
        "publishAarPublicationToLocalMavenWithChecksumsRepository",
        "publishJarReleasePublicationToLocalMavenWithChecksumsRepository",
        "publishAarPublicationToMavenLocal",
        "publishJarReleasePublicationToMavenLocal",
        "publishAarPublicationToInji-openid4vpRepository",
        "publishJarReleasePublicationToInji-openid4vpRepository"
    )

    publishTasks.forEach { publishName ->
        tasks.findByName(publishName)?.dependsOn(signTasks[0], signTasks[1])
    }
}

apply(from = "publish-artifact.gradle")
var buildDir = project.layout.buildDirectory.get()
sonarqube {
    properties {
        property("sonar.java.binaries", "$buildDir/classes/kotlin/jvm/main, $buildDir/tmp/kotlin-classes/debug")
        property("sonar.language", "kotlin")
        property("sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property("sonar.scm.disabled", "true")
        property("sonar.coverage.jacoco.xmlReportPaths",
            "$buildDir/reports/jacoco/jacocoMergedReport/jacocoMergedReport.xml")
        property("sonar.sources", "src/commonMain/kotlin,src/jvmMain/kotlin,src/androidMain/kotlin")
        property("sonar.tests", "src/commonTest/kotlin,src/jvmTest/kotlin,src/androidUnitTest/kotlin")
    }
}
