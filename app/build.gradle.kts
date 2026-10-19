plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "shivyt.android.adshield"
    compileSdk = 36

    defaultConfig {
        applicationId = "shivyt.android.adshield"
        minSdk = 23
        targetSdk = 36
        versionCode = 15
        versionName = "0.7.3"
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// No external dependencies: UI is plain Android views and the VPN engine is
// framework-only, which keeps the APK tiny and TV-friendly.
dependencies {
}
