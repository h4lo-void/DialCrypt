plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing comes from the environment (tools/android-build/build.sh sets these).
// When any of the three is missing the release build stays unsigned, as before.
val aegisKeystore: String? = System.getenv("AEGIS_KEYSTORE")?.takeIf { it.isNotBlank() }
val aegisKeystorePass: String? = System.getenv("AEGIS_KEYSTORE_PASS")?.takeIf { it.isNotBlank() }
val aegisKeyAlias: String? = System.getenv("AEGIS_KEY_ALIAS")?.takeIf { it.isNotBlank() }
val aegisSigningConfigured = aegisKeystore != null && aegisKeystorePass != null && aegisKeyAlias != null

// Test switches. They only reach the fieldTest build type; release always has them off.
// AEGIS_TEST_NO_PIN=1: the vault opens with a built-in PIN and no PIN screen is shown (core/TestNoPin.kt).
// AEGIS_FIELD_TEST=1: soft single-use PIN tickets are accepted and the line probe reads files from filesDir.
val aegisTestNoPin = System.getenv("AEGIS_TEST_NO_PIN") == "1"
val aegisFieldTest = System.getenv("AEGIS_FIELD_TEST") == "1"

android {
    namespace = "io.github.h4lovoid.dialcrypt"
    compileSdk = 35

    defaultConfig {
        minSdk = 34
        targetSdk = 35
        versionCode = 100
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    if (aegisSigningConfigured) {
        signingConfigs {
            create("aegisRelease") {
                storeFile = file(aegisKeystore!!)
                storePassword = aegisKeystorePass
                keyAlias = aegisKeyAlias
                keyPassword = aegisKeystorePass
            }
        }
    }

    buildTypes {
        getByName("debug") {
            // Debug builds run against the fake core; the test switches stay off.
            buildConfigField("boolean", "TEST_NO_PIN", "false")
            buildConfigField("boolean", "FIELD_TEST_SOFT_TICKETS", "false")
            buildConfigField("boolean", "FIELD_TEST_LINK_PROBE", "false")
            // Settings show the "Phone app" section (default dialer role) in debug builds.
            buildConfigField("boolean", "DIALER_ROLE_UI", "true")
            // The default dialer components (dial pad, in-call service, screening, missed calls) are enabled.
            manifestPlaceholders["dialerComponentsEnabled"] = "true"
        }
        getByName("release") {
            // Shrink and optimize the release build. proguard-rules.pro keeps everything outside the ui
            // package whole, because native code, the manifest and the other processes reach it by name.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (aegisSigningConfigured) {
                signingConfig = signingConfigs.getByName("aegisRelease")
            }
            // Hard-wired off: a release build can never carry a test switch, whatever the environment says.
            buildConfigField("boolean", "TEST_NO_PIN", "false")
            buildConfigField("boolean", "FIELD_TEST_SOFT_TICKETS", "false")
            buildConfigField("boolean", "FIELD_TEST_LINK_PROBE", "false")
            // No "Phone app" section until the default dialer has passed the on-device checks.
            buildConfigField("boolean", "DIALER_ROLE_UI", "false")
            // The default dialer components are disabled in the manifest, so the system cannot offer the role.
            manifestPlaceholders["dialerComponentsEnabled"] = "false"
        }
        // Release code and signing, plus the test switches from the environment. Never for real use.
        create("fieldTest") {
            initWith(getByName("release"))
            versionNameSuffix = "-fieldtest"
            matchingFallbacks += listOf("release")
            if (aegisSigningConfigured) {
                signingConfig = signingConfigs.getByName("aegisRelease")
            }
            // Field-test builds only (AEGIS_FIELD_TEST=1): accept phones whose key store limits
            // single-use PIN tickets in software because the secure hardware does not declare
            // android.hardware.keystore.single_use_key.
            buildConfigField("boolean", "FIELD_TEST_SOFT_TICKETS", aegisFieldTest.toString())
            // Field-test builds only (AEGIS_FIELD_TEST=1): the line probe and the narrowband gear switch read their files from filesDir.
            buildConfigField("boolean", "FIELD_TEST_LINK_PROBE", aegisFieldTest.toString())
            // Test builds only (AEGIS_TEST_NO_PIN=1): the vault opens with a built-in PIN and no PIN screen is shown.
            buildConfigField("boolean", "TEST_NO_PIN", aegisTestNoPin.toString())
            // Field-test builds show the "Phone app" section so the default dialer can be tried on a device.
            buildConfigField("boolean", "DIALER_ROLE_UI", "true")
            manifestPlaceholders["dialerComponentsEnabled"] = "true"
        }
    }

    sourceSets {
        // fieldTest is the release app with test switches: it compiles the release sources (real cores).
        maybeCreate("fieldTest").apply {
            java.srcDir("src/release/java")
        }
    }

    flavorDimensions += "security"
    productFlavors {
        create("pixelTitan") {
            dimension = "security"
            applicationId = "io.github.h4lovoid.dialcrypt"
            buildConfigField("boolean", "REQUIRE_TITAN_M2", "true")
            buildConfigField("String", "EDITION_NAME", "\"DialCrypt Pixel Titan M2\"")
            resValue("string", "app_name", "DialCrypt")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
}

androidComponents {
    // The release variant has no fake core, so its unit tests would not compile; they are not used.
    beforeVariants(selector().withBuildType("release")) { variant ->
        variant.enableUnitTest = false
    }
    // fieldTest compiles the release sources, so the same applies.
    beforeVariants(selector().withBuildType("fieldTest")) { variant ->
        variant.enableUnitTest = false
    }
}

// A release artifact must never be built while a test switch is set: the switches would be silently
// ignored and the result mistaken for a test build. Use assemblePixelTitanFieldTest instead.
val releaseArtifactTasks = Regex("^(assemble|bundle|package|install)PixelTitanRelease$")
val appProjectPath = project.path
gradle.taskGraph.whenReady {
    if (!aegisTestNoPin && !aegisFieldTest) return@whenReady
    val blocked = allTasks.filter { task ->
        task.path.substringBeforeLast(':').ifEmpty { ":" } == appProjectPath &&
            releaseArtifactTasks.matches(task.name)
    }
    if (blocked.isNotEmpty()) {
        throw GradleException(
            "AEGIS_TEST_NO_PIN or AEGIS_FIELD_TEST is set, but the task graph builds a release artifact (" +
                blocked.joinToString { it.path } + "). Release builds never carry test switches. " +
                "Build the field-test variant with :app:assemblePixelTitanFieldTest, or unset both variables.",
        )
    }
}

tasks.withType<Test>().configureEach {
    maxHeapSize = "1g"
    systemProperty("roborazzi.test.record", "true")
    systemProperty("aegis.previewDir", layout.buildDirectory.dir("ui-preview").get().asFile.absolutePath)
    systemProperty("aegis.resDir", layout.projectDirectory.dir("src/main/res").asFile.absolutePath)
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    // Adding a contact in person: camera preview and frames (CameraX) and an offline QR decoder (ZXing core, pure Java).
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("com.google.zxing:core:3.5.3")

    // Test-only: JVM unit tests and screenshots (Robolectric + Roborazzi).
    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("io.github.takahirom.roborazzi:roborazzi:1.26.0")
    testImplementation("io.github.takahirom.roborazzi:roborazzi-compose:1.26.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
