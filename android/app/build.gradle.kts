plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.compose.compiler)
}

android {
    val appVersionName: String = run {
        val vf = rootProject.file("../VERSION")
        if (vf.exists()) vf.readText().trim() else "2.0.0"
    }

    namespace = "io.github.jakharamit44.glidedrop"
    compileSdk = 37
    defaultConfig {
        applicationId = "io.github.jakharamit44.glidedrop"
        minSdk = 31
        targetSdk = 37
        versionCode = 260
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
  androidTestImplementation(composeBom)

  // Core Android dependencies
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.activity.compose)

  // Arch Components
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.viewmodel.compose)

  // Compose
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.compose.material3)
  // Tooling
  debugImplementation(libs.androidx.compose.ui.tooling)
  // Instrumented tests
  androidTestImplementation(libs.androidx.compose.ui.test.junit4)
  debugImplementation(libs.androidx.compose.ui.test.manifest)

  // Local tests: jUnit, coroutines, Android runner
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)

  // Instrumented tests: jUnit rules and runners
  androidTestImplementation(libs.androidx.test.core)
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.androidx.test.espresso.core)
}
