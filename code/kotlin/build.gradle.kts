plugins {
    kotlin("jvm") version "1.6.10"
    kotlin("plugin.serialization") version "1.6.10"
    application
}

group = "com.benchmark"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core:1.6.7")
    implementation("io.ktor:ktor-server-netty:1.6.7")
    implementation("io.ktor:ktor-auth:1.6.7")
    implementation("io.ktor:ktor-auth-jwt:1.6.7")
    implementation("io.ktor:ktor-serialization:1.6.7")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.3.2")
    implementation("ch.qos.logback:logback-classic:1.2.8")
}

application {
    mainClass.set("AuthServiceKt")
}
