import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.reimen.cifra"
    compileSdk = 34

    val keystorePropertiesFile = file("/home/reimen/Escritorio/Projects/play-pause-apk/keystore.properties")
    val keystoreProps = Properties()
    if (keystorePropertiesFile.exists()) {
        keystoreProps.load(FileInputStream(keystorePropertiesFile))
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                val storeFileStr = keystoreProps["storeFile"] as String? ?: ""
                var sf = file(storeFileStr)
                if (!sf.exists() && keystorePropertiesFile.parentFile != null) {
                    val fallback = file(keystorePropertiesFile.parentFile.absolutePath + "/app/" + storeFileStr)
                    if (fallback.exists()) sf = fallback
                }
                storeFile = sf
                storePassword = keystoreProps["storePassword"] as String? ?: ""
                keyAlias = keystoreProps["keyAlias"] as String? ?: ""
                keyPassword = keystoreProps["keyPassword"] as String? ?: ""
            }
        }
    }

    defaultConfig {
        applicationId = "com.reimen.cifra"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    testOptions {
        unitTests.all {
            it.maxHeapSize = "2g"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // Argon2id — Bouncy Castle (no existe en la JCA estándar de Android)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // org.json: provisto por la plataforma Android en runtime; jar para los tests JVM puros
    testImplementation("org.json:json:20180813")

    testImplementation("junit:junit:4.13.2")
}
