import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.jmh)
    alias(libs.plugins.detekt)
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        optIn.add("kotlin.ExperimentalUnsignedTypes")
    }
}

dependencies {
    implementation(project(":library"))
    implementation(libs.cryptography.core)
    implementation(libs.cryptography.jdk)
    implementation(libs.cryptography.random)

    jmh("org.openjdk.jmh:jmh-core:${libs.versions.jmh.get()}")
    jmh("org.openjdk.jmh:jmh-generator-annprocess:${libs.versions.jmh.get()}")
}

jmh {
    warmupIterations = 3
    iterations = 5
    fork = 1
    benchmarkMode = listOf("thrpt")
    timeUnit = "s"
}
