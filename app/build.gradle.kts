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

    // Resolved against the Gradle root project, so a fresh clone builds on any
    // machine and `storeFile` is read relative to the same directory that holds
    // keystore.properties. Both files are gitignored, so nothing is committed.
    val keystorePropertiesFile = rootProject.file("keystore.properties")
    val keystoreProps = Properties()
    if (keystorePropertiesFile.exists()) {
        keystoreProps.load(FileInputStream(keystorePropertiesFile))
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile", ""))
                storePassword = keystoreProps.getProperty("storePassword", "")
                keyAlias = keystoreProps.getProperty("keyAlias", "")
                keyPassword = keystoreProps.getProperty("keyPassword", "")
            }
        }
    }

    defaultConfig {
        applicationId = "com.reimen.cifra"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    lint {
        // `FlowOperatorInvokedInComposition` revienta el análisis con
        // `InconsistentKotlinMetadataException` al leer el metadata que escribe
        // Kotlin 2.0.20: es un fallo de lint, no del código (el propio mensaje de
        // lint lo dice). Se dispara analizando `CryptoViewModel.kt`, que no tiene una sola
        // función @Composable.
        //
        // Lo que ese detector vigila es invocar operadores de Flow dentro de una
        // composición. Aquí no ocurre: la pantalla usa el patrón correcto,
        // `state.collectAsStateWithLifecycle()` en MainScreen.kt, y los operadores
        // viven en el ViewModel. Perder la comprobación no deja nada sin cubrir.
        disable += "FlowOperatorInvokedInComposition"
    }
    testOptions {
        // Robolectric necesita los recursos y assets de la app para simular un
        // `Context` real en los tests de la capa SAF.
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.maxHeapSize = "2g"
            // `tools/interop/verify.sh` pasa -PinteropOut para exportar sobres y
            // comprobarlos contra Encrypt-C++. Fuera de ese script la propiedad
            // no existe y el test de exportación se salta solo.
            if (project.hasProperty("interopOut")) {
                it.systemProperty("interopOut", project.property("interopOut").toString())
            }
            it.testLogging {
                events("failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")

    // ACOPLADO A COMPOSE: 2.8.0 movió `LocalLifecycleOwner` de
    // `androidx.compose.ui.platform` a `androidx.lifecycle.compose`, y
    // `collectAsStateWithLifecycle()` pasó a leer el nuevo. Compose 1.7.0 es lo
    // que añade el puente que hace que ambos sean el mismo valor.
    //
    // Con Compose 1.6.8 (el BOM de abajo) y lifecycle 2.8.x el release
    // **reventaba al arrancar**: `IllegalStateException: CompositionLocal
    // LocalLifecycleOwner not present`. Rompió el 24 de julio de 2024 y no se ve
    // en los tests de JVM, solo al lanzar en un dispositivo.
    //
    // Dos salidas: subir el BOM a 2024.09.00 (Compose 1.7), o bajar lifecycle a
    // 2.7.0, que es lo que se hace aquí porque el BOM está fijado a propósito
    // (Material3 1.2.1, sin `surfaceContainer*`). Si suben el BOM, hay que quitar
    // lifecycle de esta lista; si suben lifecycle, hay que subir el BOM.
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Argon2id — Bouncy Castle (no existe en la JCA estándar de Android)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // org.json: provisto por la plataforma Android en runtime; jar para los tests JVM puros
    testImplementation("org.json:json:20180813")

    testImplementation("junit:junit:4.13.2")

    // `Sources` es la única capa que habla con `ContentResolver`, y sin esto lo
    // único que se podía hacer con ella era probarla a mano en un dispositivo.
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core-ktx:1.6.1")

    // Tests de UI en un dispositivo de verdad.
    //
    // Existen porque los dos bugs que se encontraron a mano en el móvil NO se veían
    // en los 188 tests de JVM: el crash de `LocalLifecycleOwner` al arrancar (una
    // incompatibilidad de versiones que solo aparece al montar la ventana) y el
    // botón de pegar que no existía, que dejaba el camino de texto inalcanzable.
    // Los dos eran de la capa Compose, y esa capa no tenía ni un test.
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.06.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.1")
    androidTestImplementation("androidx.test:rules:1.6.1")

    // La actividad que usa `createAndroidComposeRule` para los tests.
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
