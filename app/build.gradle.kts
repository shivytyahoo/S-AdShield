import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "shivyt.android.adshield"
    // Compose 1.13 / lifecycle 2.11 require compiling against API 37;
    // targetSdk stays 36 (no new runtime behaviour opted into).
    compileSdk = 37

    defaultConfig {
        applicationId = "shivyt.android.adshield"
        // Compose 1.13 / material3 1.5 require minSdk 24 (was 23).
        minSdk = 24
        targetSdk = 36
        versionCode = 53
        versionName = "1.2.0"
    }

    signingConfigs {
        create("release") {
            // Keystore + password live OUTSIDE this project dir and are
            // never pushed to GitHub (see push_incremental.py scope).
            storeFile = file(
                "/home/hatch/workspace/shiv-all-projects/build-work/adshield/signing/adshield-release.keystore"
            )
            storePassword = File(
                "/home/hatch/workspace/shiv-all-projects/build-work/adshield/signing/keystore-password.txt"
            ).readText().trim()
            keyAlias = "adshield"
            keyPassword = File(
                "/home/hatch/workspace/shiv-all-projects/build-work/adshield/signing/keystore-password.txt"
            ).readText().trim()
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom-alpha:2026.08.00")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
}
