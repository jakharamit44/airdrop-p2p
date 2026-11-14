plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.compose.compiler)
}

android {
    val appVersionName: String = run {
        val vf = rootProject.file("../VERSION")
        if (vf.exists()) vf.readText().trim() else "2.0.0"
    }
    val versionParts = appVersionName.split(".").map { it.toIntOrNull() ?: 0 }
    val appVersionCode = (versionParts.getOrElse(0) { 3 } * 100) +
        (versionParts.getOrElse(1) { 0 } * 10) +
        versionParts.getOrElse(2) { 0 }

    namespace = "io.github.jakharamit44.glidedrop"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.github.jakharamit44.glidedrop"
        minSdk = 31
        targetSdk = 37
        versionCode = appVersionCode
        versionName = appVersionName
    }

    val releaseKeystorePath = providers.environmentVariable("GLIDEDROP_KEYSTORE_PATH").orNull?.trim()?.takeIf { it.isNotEmpty() }
    val releaseStorePassword = providers.environmentVariable("GLIDEDROP_KEYSTORE_PASSWORD").orNull
    val releaseKeyAlias = providers.environmentVariable("GLIDEDROP_KEY_ALIAS").orNull?.trim()?.takeIf { it.isNotEmpty() }
    val releaseKeyPassword = providers.environmentVariable("GLIDEDROP_KEY_PASSWORD").orNull?.takeIf { it.isNotEmpty() } ?: releaseStorePassword
    val hasReleaseSigning = releaseKeystorePath != null &&
        file(releaseKeystorePath).isFile &&
        !releaseStorePassword.isNullOrEmpty() &&
        releaseKeyAlias != null &&
        !releaseKeyPassword.isNullOrEmpty()

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseKeystorePath)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
      compose = true
      aidl = false
      buildConfig = false
      shaders = false
    }

    packaging {
      resources {
        excludes += "/META-INF/{AL2.0,LGPL2.1}"
      }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
  val composeBom = platform(libs.androidx.compose.bom)
  implementation(composeBom)

  // Core Android dependencies
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.activity.compose)

  // Compose
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.material3)

  // Local tests: jUnit, coroutines
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}
