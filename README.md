# Cifra

App Android (Kotlin + Jetpack Compose) de cifrado con un único esquema:
**XChaCha20-Poly1305 + Argon2id**. 100 % offline, sin red, sin backend, sin
telemetría.

Cifra **texto y archivos de cualquier tamaño** con la misma operación: la
memoria que usa es constante, así que un archivo de 40 GB se cifra igual de bien
que un texto de 40 bytes.

<p align="center">
  <a href="https://github.com/disruptorh/Encrypt-apk/releases/latest/download/Cifra.1.3.apk">
    <img alt="Descargar" src="https://img.shields.io/badge/%E2%AC%87%20Download-latest%20release-2f6feb?style=for-the-badge&logo=github&logoColor=white">
  </a>
  <a href="https://github.com/disruptorh/Encrypt-apk/releases/latest">
    <img alt="Versiones" src="https://img.shields.io/github/v/release/disruptorh/Encrypt-apk?label=release&style=flat&logo=github&logoColor=white">
  </a>
  <a href="./LICENSE">
    <img alt="Licencia" src="https://img.shields.io/badge/licencia-Apache--2.0-blue?style=flat">
  </a>
</p>

## 📥 Descarga rápida

**[`Cifra.1.3.apk`](https://github.com/disruptorh/Encrypt-apk/releases/latest/download/Cifra.1.3.apk)**
— APK firmado, listo para instalar en Android 8.0 o superior.

Para instalarlo a mano: cópialo al móvil y ábrelo desde el explorador de
archivos (hay que permitir «instalar apps de orígenes desconocidos» para el
gestor de archivos), o pásalo por `adb` si lo tienes conectado:

```bash
# 1. Descargar la última release (el nombre del asset no cambia nunca)
curl -L -o Cifra.apk https://github.com/disruptorh/Encrypt-apk/releases/latest/download/Cifra.1.3.apk

# 2. Instalar en el móvil conectado por USB (con depuración USB activada)
adb install -r Cifra.apk
```

Si prefieres no compilar y ya tienes el APK en el móvil, esto es todo: no pide
permisos, no hay cuenta, no hay configuración inicial.

## 🚀 Uso rápido

La app tiene **una sola pantalla**.

1. Elige **Cifrar** o **Descifrar**.
2. Pega el contenido o elige un archivo con el selector del sistema (SAF). La app
   solo lee y escribe donde le dejan: no toca nada fuera de lo que tú elijas.
3. Escribe la contraseña (obligatoria) y, si quieres, un *campo secreto
   adicional* (pepper).
4. Pulsa **CIFRAR** / **DESCIFRAR**.

Si el resultado es pequeño lo verás en pantalla, con botones para copiarlo o
guardarlo. Si no cabe —porque el archivo es grande o porque el proveedor de
documentos no declara el tamaño— te pedirá un archivo de destino antes de
empezar.

El sobre lleva dentro los parámetros del KDF, así que algo cifrado con el perfil
Estándar se puede descifrar aunque el perfil por defecto cambie. No hace falta
recordar qué perfil se usó.

## 📦 Compilar desde código

La raíz del repositorio **es** el proyecto Gradle: no hay subdirectorio
`android/`, así que todos los comandos se ejecutan desde la raíz.

### Requisitos

| Qué | Versión |
|---|---|
| JDK | 17 (`sourceCompatibility`/`jvmTarget` = `17`) |
| Android Gradle Plugin | 8.9.1 |
| Kotlin | 2.0.20 (+ plugin de Compose) |
| Gradle | 8.11.1, vía wrapper (no hace falta instalarlo) |
| Android SDK | plataforma **34**, `minSdk 26`, `targetSdk 34` |
| Herramientas de línea de comandos del SDK | `sdkmanager`, `platform-tools` (`adb`) |

Android Studio Ladybug o posterior abre el proyecto tal cual y trae su propio
JDK, así que instalar solo el SDK y el JDK 17 es suficiente.

**`local.properties`**: el SDK se localiza por el fichero `local.properties` de
la raíz, que está en `.gitignore` y por eso no viene en el clon. Créalo con la
ruta **de tu máquina**:

```bash
# 1. Crear local.properties apuntando a tu SDK (cambia la ruta si no es esta)
printf 'sdk.dir=%s\n' "$HOME/Android/Sdk" > local.properties

# 2. Comprobar que ha quedado bien
cat local.properties
```

La ruta que trae el repositorio publicado no te sirve: es la del equipo que
compiló el APK y en tu equipo ese directorio no existe. Si tienes el SDK en otro
sitio (por ejemplo `/opt/android-sdk`), sustituye `$HOME/Android/Sdk` por esa
ruta. Android Studio escribe este fichero solo al abrir el proyecto.

### Clonar

```bash
# 1. Clonar el repositorio
git clone https://github.com/disruptorh/Encrypt-apk.git
cd Encrypt-apk
```

### Dependencias

Paquetes del SDK que hacen falta (Debian/Ubuntu; en Android Studio, SDK Manager):

```bash
# 1. Aceptar las licencias del SDK (una sola vez)
yes | sdkmanager --licenses

# 2. Instalar la plataforma 34 y las platform-tools (adb)
sdkmanager "platforms;android-34" "platform-tools"
```

Las build-tools las elige el AGP solo; no hay versión fijada en el proyecto.

### Compilar

**El camino recomendado** es el script de la raíz: pasa los tests, compila el
release y comprueba que el APK va firmado.

```bash
# 1. Build completo: tests unitarios + APK release + comprobación de firma
chmod +x build_apk.sh
./build_apk.sh
```

Sin permisos de ejecución también vale `./build_apk.sh` si lanzas el intérprete:
`bash build_apk.sh`.

El APK release queda en:

```text
app/build/outputs/apk/release/app-release.apk
```

**Sin `keystore.properties` el release sale sin firmar** y por eso
`build_apk.sh` termina con error en el paso de firma (el APK se ha generado, pero
no se puede instalar). La sección [🔐 Seguridad y firma](#-seguridad-y-firma)
tiene el bloque para crear un keystore de pruebas.

Para probar en el dispositivo puedes ir directo al APK debug, que sí va firmado
con la clave de depuración:

```bash
# 1. APK debug (firmado con la clave de depuración, instalable tal cual)
./gradlew :app:assembleDebug
```

```text
app/build/outputs/apk/debug/app-debug.apk
```

### Ejecutar los tests

```bash
# 1. Tests unitarios en la JVM (188 tests)
./gradlew :app:testDebugUnitTest
```

Qué cubren:

| Fichero | Tests | Cubre |
|---|---|---|
| `Argon2KdfTest.kt` | 13 | Vector oficial de **Argon2id RFC 9106** (Apéndice A.3), binding de pepper, rangos fuera de límite |
| `Base64UrlTest.kt` | 8 | Longitudes exactas, arrastres de 1–3 bytes entre trozos, equivalencia con el camino de una pasada |
| `ChaCha20Poly1305PrimitiveTest.kt` | 10 | Vectors de ChaCha20 (RFC 8439) y Poly1305, endianess, claves y máscaras |
| `CryptoEngineTest.kt` | 21 | Round-trip: texto vacío, 1 char, 10 KB, emojis/UTF-8, con/sin pepper. Negativos: contraseña incorrecta, pepper incorrecto, ciphertext corrupto. Presupuesto de memoria |
| `CryptoEngineStreamingTest.kt` | 9 | Streaming con archivos reales, bytes idénticos a la API de una pasada, tag roto detectado al final y nada publicado |
| `EnvelopeStreamingTest.kt` | 14 | Escritor streaming idéntico byte a byte al de memoria, lector con lecturas de 1 byte, tolerancia a whitespace, rechazos (truncado, basura final, terminador roto), y sobre sin tamaño declarado |
| `EnvelopeTest.kt` | 13 | Fuzzing del parser: JSON malformado, Base64 inválido, campos ausentes, claves no permitidas, parámetros fuera de rango |
| `ConstantMemoryTest.kt` | 4 | Memoria constante medida: 256 MiB de entrada con techo de KDF + 16 MiB, independencia del pico al ×4, presupuesto `IN_MEMORY`/`STREAMED`, y el contrato de `open` de `startDecrypting` |
| `InteropExportTest.kt` | 1 | Exportador de interoperabilidad; **se salta** salvo que se le pase `-PinteropOut` |
| `InteropVectorsTest.kt` | 6 | Interoperabilidad real con Encrypt-C++: serialización idéntica byte a byte, descifrado de blobs de C++, paridad streaming/una pasada, negativos |
| `PlanTest.kt` | 25 | Decisiones de la UI sin Android: cotas de tamaño, UTF-8 exacto, memoria o archivo, recorte del nombre de destino y sus casos límite |
| `Poly1305DiagnosticTest.kt` | 4 | Casos límite de bloque y alineación del acumulador |
| `AsciiTextStreamTest.kt` | 13 | El texto pegado se decodifica en streaming: bytes idénticos, trozos arbitrarios, espacios del interior, ASCII inválido, y un sobre de 12 MiB leído con memoria constante |
| `SourcesTest.kt` | 31 | Capa SAF con Robolectric y un `ContentProvider` real: modo de escritura, `SIZE`/`DISPLAY_NAME` por proyección, tamaños desconocidos, proveedores que fallan, `readIfSmall` sin truncar, temporales privados |
| `XChaCha20Poly1305StreamingTest.kt` | 10 | AEAD en trozos contra una sola pasada, tag truncado, partición arbitraria |
| `XChaCha20Poly1305Test.kt` | 6 | Vectors de HChaCha20 y AEAD, nonce de 24 bytes, tag truncado |

Son 188 tests, de los que 1 se salta solo (el exportador, que solo actúa con
`-PinteropOut`). Los tests corren con `-Xmx2g` porque el de memoria constante
mueve 256 MiB.

En un móvil de verdad, con el dispositivo conectado:

```bash
# 1. Tests de instrumentación (Compose) — 4 tests de UI
./gradlew :app:connectedDebugAndroidTest
```

| Test | Qué cubre |
|---|---|
| `laAppArrancaYMuestraLaPantalla` | Regresión del crash `LocalLifecycleOwner not present`. Compilaba, el release se firmaba y los 188 tests de JVM pasaban; solo montaba la ventana en un dispositivo y peta |
| `pegarTraeElTextoAlCampo` | Regresión del camino de texto inalcanzable: sin botón de pegar no había forma de meter texto a mano |
| `sePuedeCifrarYDescifrarUnTextoCorto` | El recorrido completo sin SAF: cifrar, leer el sobre y descifrarlo |
| `sinContrasenaNoSaleNada` | Sin contraseña no se ejecuta nada, comprobado por el efecto y no por el texto del aviso (el Snackbar se va solo y daría tests que fallan por tiempo) |

Existen por un motivo concreto: los dos bugs más molestos que aparecieron se
encontraron a mano en el móvil y **no los veía ningún test de JVM**. Los dos
eran de la capa Compose, que no tenía ninguno. Para que no dependan de los
textos visibles hay `Tags` en `ui/Theme.kt` (`CONTENT`, `PASSWORD`, `PEPPER`,
`PASTE`, `RUN`, `RESULT`).

### Ejecutar la aplicación

```bash
# 1. APK debug en el dispositivo conectado
./gradlew :app:installDebug
```

O instalar a mano un APK ya compilado:

```bash
# 1. Instalar el debug (va firmado con la clave de depuración)
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 2. Instalar el release, si lo has firmado con un keystore propio
adb install -r app/build/outputs/apk/release/app-release.apk
```

`adb install -r` sustituye la versión anterior conservando los datos. Con el
release **sin firmar** falla: ese es el síntoma del APK sin keystore.

## 🧰 Comandos útiles

```bash
# 1. Build recomendado: tests + APK release + comprobación de firma
./build_apk.sh

# 2. Solo tests
./gradlew :app:testDebugUnitTest

# 3. APK debug
./gradlew :app:assembleDebug

# 4. APK release (sin la comprobación de firma; sale sin firmar si no hay keystore)
./gradlew :app:assembleRelease

# 5. Instalar el debug en el móvil conectado
./gradlew :app:installDebug

# 6. Lint
./gradlew :app:lintDebug

# 7. Tests de UI en el dispositivo
./gradlew :app:connectedDebugAndroidTest

# 8. Verificar la firma de un APK (busca el apksigner más nuevo del SDK)
find "$HOME/Android/Sdk/build-tools" -name apksigner -type f | sort -V | tail -1 | xargs -I{} {} verify --print-certs app/build/outputs/apk/release/app-release.apk
```

**Verificar la interoperabilidad contra Encrypt-C++ en caliente** (solo si
tienes ese repositorio compilado con `build/libencrypt_core.a`):

```bash
# 1. Interop bidireccional Kotlin <-> C++ (indica dónde está Encrypt-C++)
CPP_ROOT=/ruta/a/Encrypt-C++ tools/interop/verify.sh
```

## 🗂️ Estructura del proyecto

```text
.
├── app/
│   ├── build.gradle.kts          ← compileSdk 34, minSdk 26, targetSdk 34, firma
│   ├── proguard-rules.pro
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── java/com/reimen/cifra/
│       │   │   ├── crypto/      ← Kotlin puro, sin Android (testeable con JUnit)
│       │   │   ├── data/Sources.kt  ← SAF: abrir, tamaño, temporales, publicar
│       │   │   ├── ui/          ← ViewModel, pantalla Compose, tema
│       │   │   └── MainActivity.kt  ← FLAG_SECURE + tema
│       │   └── res/             ← temas (values, -night, -v27, -night-v27), icono
│       ├── test/                ← 188 tests JVM (vectores RFC 9106 incluidos)
│       └── androidTest/         ← 4 tests de UI en dispositivo
├── tools/
│   └── interop/                 ← puente y script contra Encrypt-C++
├── build_apk.sh                 ← tests + release + comprobación de firma v2/v3
├── gradle/wrapper/              ← Gradle 8.11.1
├── build.gradle.kts             ← AGP 8.9.1, Kotlin 2.0.20
├── settings.gradle.kts          ← proyecto "Cifra", solo el módulo :app
└── gradle.properties
```

## 🧬 Decisiones técnicas

### Esquema

| Componente | Elección |
|---|---|
| Cifrado | XChaCha20-Poly1305 (IETF, tag de 16 bytes) — `aead: xchacha20poly1305_ietf` |
| KDF | Argon2id v1.3 (RFC 9106) con **parallelism = 1** |
| Pepper | No va al KDF: se enlaza después con **BLAKE2b keyed** (paridad con libsodium) |
| Salt | 16 bytes `SecureRandom` por cifrado |
| Nonce | 24 bytes `SecureRandom` por cifrado (XChaCha20 admite reutilización con menos riesgo que ChaCha20) |
| AAD | Los parámetros del KDF (`v`, `aead`, `kdf`, `ops`, `mem_kib`) van autenticados **dentro del tag**: un ataque que los altere rompe la verificación |
| Formato | JSON (`v, aead, kdf, ops, mem_kib, salt, nonce, ciphertext`) → Base64 URL-safe sin padding |
| Serialización | A mano, con lista blanca de campos: rechaza JSON con claves extra |

Dependencias: Compose BOM 2024.06.00, `bcprov-jdk18on:1.78.1`,
lifecycle 2.7.0, activity-compose 1.9.0, documentfile 1.0.1, y
`android:largeHeap="true"` (necesario para el perfil de 256 MiB).

### Perfiles de fuerza

| Perfil | Memoria | Iteraciones |
|---|---|---|
| Estándar | 64 MiB (65536 KiB) | 3 |
| Máxima | 256 MiB (262144 KiB) | 6 |

`parallelism` no viaja en el sobre porque está fijado a `1` en ambos lados: es
lo que exige libsodium para ser interoperable.

### Archivos grandes: por qué no se nota la diferencia

El sobre es un Base64 que envuelve un JSON que envuelve otro Base64. Recorrerlo
"entero en memoria" habría significado copiar el archivo cuatro veces. Todo el
camino de archivos es incremental:

```text
archivo → Base64Url.Decoder → bytes del JSON → HeaderScanner → Base64Url.Decoder
        → XChaCha20Poly1305 → archivo
```

Piezas que lo hacen posible:

- **`Base64Url.Decoder` y `.Encoder` son `OutputStream`/`InputStream`**, con
  estado de arrastre entre llamadas. `Encoder` hereda de `OutputStream`, así que
  se puede envolver un flujo de salida real y no un `ByteArray`.
- **`HeaderScanner`** reconoce la cabecera JSON en cuanto entra la comilla que
  abre el valor de `"ciphertext"`. Los otros campos miden ~200 bytes; el
  ciphertext es el 99 % del sobre, así que se localiza dónde empieza sin leer
  ni un kilobyte de más. Si se queda corto, pide más datos en vez de fallar.
- **`streamCiphertext()`** encuentra el final real del campo por sus
  delimitadores (`"` o `}` no son caracteres Base64 válidos) en vez de fiarse de
  la aritmética.
- **`CryptoEngine.startEncrypting()` / `startDecrypting()`** devuelven una sesión
  con `write(chunk, off, len)` / `consume(chunk)` y `finish()`. El motor retiene
  los **últimos 16 bytes** hasta verificar el tag, porque hasta ese momento el
  plaintext es del atacante y no puede publicarse.
- **`Utf8Writer`** para el texto pegado: si un emoji cae justo en el límite de un
  búfer, el par surrogata partido se resuelve en el trozo siguiente en vez de
  convertirse en dos `?`.

El resultado es que el camino de streaming y el de memoria producen **el mismo
sobre byte a byte**, y eso es exactamente lo que comprueban los tests.

### Las decisiones de la UI también se prueban

`ui/Plan.kt` es Kotlin puro, sin Android, y contiene lo que la pantalla *decide*
—no lo que ejecuta—: cuánto va a ocupar el resultado, si cabe en pantalla o va a
archivo, y cómo se llama el archivo de destino. Vive aparte del ViewModel
precisamente para poder probarlo en la JVM normal, igual que `crypto/`.

Dos cosas que estaban mal y que ahora hay tests que las fijan:

- **El total del progreso estaba en unidades distintas al contador.** El contador
  `done` cuenta bytes de texto plano, pero el total venía de `upperBoundFor`, que
  es el tamaño del *sobre* (≈ ×16/9). La barra del progreso de cifrado no podía
  pasar de 9/16 = **56 %**. Ahora el total es el texto plano, que es lo que
  cuenta el contador, y para texto se mide el UTF-8 exacto con `Plan.utf8Length`
  (`O(n)` en tiempo, `O(1)` en memoria; `toByteArray(UTF_8)` reservaría un array
  del tamaño del texto, justo lo que esta app evita).
- **El tamaño del texto se estimaba contando unidades UTF-16 como si fueran
  bytes.** Un emoji son 2 unidades y 4 bytes, así que un texto con emojis se
  estimaba a la mitad de su valor: la barra llegaba al 100 % a mitad de trabajo y
  un texto grande podía enviarse a memoria creyendo que cabía. Para decidir
  memoria o archivo se usa ahora una cota que nunca se queda corta (3 bytes por
  unidad UTF-16, que es el peor caso de UTF-8); para el progreso, la cuenta
  exacta.

`outputName` también recorta a 255 bytes contando bytes y no caracteres, y sin
partir un carácter multibyte: un nombre de 300 caracteres, o uno con acentos,
fallaba al *crear* el destino —después de que el usuario hubiera escrito la
contraseña—, y un proveedor que rechaza el nombre no siempre explica por qué.

### Tema

`ui/Theme.kt` define una paleta propia con dos esquemas completos (claro y oscuro) y
los colores extra que Material 3 no trae (`CifraTheme.colors.warning`). El tema
sigue al sistema y, en **Android 12 o superior, usa el color dinámico** (Material
You): el móvil pinta la app con su paleta y los esquemas propios quedan como
respaldo para versiones anteriores. Para forzar siempre la paleta de marca,
`CifraTheme(dynamicColor = false)`.

El marco de la ventana está repartido en cuatro carpetas de recursos, y el reparto
no es decorativo:

| Carpeta | Qué pone |
|---|---|
| `values/` | `Theme.Cifra.Base.Light` / `.Base.Dark` con los valores comunes, y `Theme.Cifra` en claro |
| `values-night/` | `Theme.Cifra` en oscuro |
| `values-v27/` | lo mismo, más `windowLightNavigationBar` (API 27) |
| `values-night-v27/` | la combinación de las dos |

Con un único `themes.xml` el modo claro pintaba las barras del sistema y el fondo
de ventana de negro sobre una app clara, con un fogonazo negro al arrancar. Y
`windowLightNavigationBar` solo puede aparecer en `values-v27/` porque el `minSdk`
es 26; sin él, en claro la barra de navegación queda clara con iconos blancos,
que es lo mismo que no tener barra.

`@color/window_background` y `@color/system_bar` están puestos a mano a los
valores de `LightScheme.background` y `DarkScheme.background`, para que el salto
al arrancar no dé un fogonazo de otro color.

### Icono

Icono adaptativo propio (`ic_launcher_foreground.xml` + `ic_launcher_background`),
en vez de `@android:drawable/ic_lock_lock`, que es un recurso del sistema y se ve
igual en cualquier app. Sin `<monochrome>` a propósito: el foreground está
dibujado con los colores de marca, así que teñirlo de un color plano no aporta
nada.

### No hay FileProvider, y es a propósito

La app usa SAF (`OpenDocument` y `CreateDocument`) de punta a punta: elige un
archivo, lo lee, y escribe en otro que el usuario nombra. En ningún momento le
pasa un `content://` a otra aplicación, así que no hay nada que compartir y no
hace falta un `FileProvider` ni un `res/xml/file_paths.xml`. Añadirlo sería código
que no se ejecuta nunca.

Lo que sí tiene el manifiesto:

- `allowBackup="false"` y `dataExtractionRules` sin nada que respaldar. Lo que la
  app guarda es texto cifrado, y que el sistema lo copie a la nube solo multiplica
  las copias de datos sensibles en el disco.
- `largeHeap="true"`, por los 64 MiB de Argon2id.
- Sin `screenOrientation`: el `ViewModel` sobrevive al giro, y bloquear a retrato
  solo estorbaría en tablets y plegables.
- Sin permiso `INTERNET`. Es criptografía local y no necesita red.

### Pegar un sobre grande: por qué casi se comía la app

Pegar texto encriptado grande era la forma más fácil de tumbar la app, y no por
el descifrado: era por lo que se hacía **antes** de descifrar. Dos sitios copiaban
el texto entero, y los dos en caliente:

1. Al mirar la cabecera del sobre para saber cuánto va a salir, se hacía
   `Base64Url.decode(texto)`. Eso reserva el sobre entero en un `ByteArray`, y
   pasaba en **cada pulsación del teclado**, no solo al pegar. Con varios
   megabytes son varios megabytes por pulsación.
2. Al empezar a descifrar, `trim().toByteArray()` hacía dos copias más del mismo
   tamaño: una del `String` y otra del `ByteArray`.

Juntas son un coste O(n) por pulsación y un pico de memoria de varias veces el
texto pegado, que es exactamente lo que se ve como "se queda temblando" y como
"se cierra". Medido sobre un sobre de 16 MB: la ruta antigua añadía 18 MB de
pico y la nueva añade 0.

Cómo está resuelto:

- **La cabecera solo se lee si el sobre es pequeño.** El tope son 64 KiB de
  caracteres, muy por encima de lo que cabe en pantalla, para no perder el tamaño
  exacto justo en los casos en que el resultado sí se enseña en el texto. Por
  encima no se intenta y el tamaño queda desconocido. No se pierde nada: un
  sobre tan largo va a un archivo de salida de todos modos, que es exactamente
  lo que decide el tamaño desconocido.
- **Al descifrar, el texto se decodifica en streaming** con `AsciiTextStream`, que
  solo tiene un buffer fijo de 32 KiB y calcula los límites del texto sin copiarlo.
- **El camino en memoria se niega a sí mismo.** `outputNeedsFile` se vuelve a
  comprobar en el `ViewModel`, no solo en la interfaz, así que un tamaño
  desconocido no puede acabar llenando un `ByteArrayOutputStream` con el
  resultado entero aunque la interfaz se equivoque.

Lo que sigue en pie: un `OutOfMemoryError` durante el trabajo se convierte en un
mensaje en pantalla, no en un cierre.

### Un detalle que salió al escribir los tests de UI

`setMode` no borra ni el texto ni la contraseña al cambiar de pestaña, y es lo
correcto: nadie quiere reescribir la contraseña cada vez que pasa de cifrar a
comprobar si un sobre es suyo. Pero tiene una consecuencia: si se pega un sobre
encima de lo que ya había, ambos textos acaban concatenados y el descifrado falla
con un error de formato que no dice dónde está el problema. Por eso **pegar
reemplaza** el contenido en vez de añadirse al final.

También estaba el otro lado: el botón de pegar solo aparecía cuando no había
nada escrito. En cuanto había texto, desaparecía y no se podía pegar otro sobre
para reemplazar el anterior, que es justo lo que hace falta al probar una
contraseña nueva. Ahora está en los dos sitios.

### La capa SAF, probada contra un `ContentResolver` de verdad

`Sources` es lo único que habla con `ContentResolver`, y se prueba con
**Robolectric**: un `Context` real de Android, no una imitación. Los documentos
los sirve un `ContentProvider` de verdad, y no los registros a mano de
`ShadowContentResolver` porque la diferencia importa: un cursor registrado a mano
devuelve siempre las mismas columnas y el shadow **se salta el modo de apertura**.
Probar contra el atajo habría dado por bueno un `Sources` que leyera `SIZE` de la
columna equivocada y otro que escribiera en modo `append`.

Lo que cubren esos 31 tests, y por qué cada caso importa:

- **Abrir un documento inexistente falla en vez de devolver un flujo vacío.** Si
  `openInput` devolviera vacío, la app cifraría un archivo vacío y diría que ha
  ido bien: el peor fallo posible, porque no parece un fallo.
- **El destino se abre en modo `wt` (truncar y escribir), comprobado mirando el
  modo que se le pide al proveedor.** `CreateDocument` puede devolver un documento
  que ya existe; en modo `append` el sobre nuevo quedaría detrás del anterior y el
  resultado sería un archivo corrupto con apariencia de válido.
- **Un tamaño desconocido se reporta como `-1`, nunca como `0`.** Un `0` se leería
  como "archivo vacío" y haría decidir en contra de escribir a disco.
- **Un proveedor que revienta o no declara metadatos no tumba la pantalla.** La app
  no puede caerse por no saber cuánto mide un archivo.
- **`readIfSmall` devuelve `null` en vez de truncar** lo que no cabe, incluso
  cuando el proveedor no declara el tamaño: un descifrado recortado a la mitad se
  parecería al texto bueno del usuario.
- **El temporal va al `cacheDir` y `publish` lo borra.** El temporal contiene
  texto descifrado en claro; si sobreviviera, se quedaría ahí para siempre.

### Medido, no supuesto

`ConstantMemoryTest` cifra y descifra un archivo de **256 MiB** mientras un hilo
muestrea el heap:

```text
cifrado:    pico 72 MiB (KDF 64 MiB + 8 MiB de streaming)
descifrado: pico 72 MiB (KDF 64 MiB + 8 MiB de streaming)
archivo:    256 MiB de entrada
```

Los 64 MiB son el Argon2id, constantes e inevitables; los 8 MiB son el camino
streaming. El test además comprueba que al multiplicar la entrada por cuatro el
pico **no** se multiplica por cuatro, que es la definición de constante. Si
alguien reintrodujera un `readBytes()` o un `ByteArrayOutputStream`, los 256 MiB
aparecerían por encima del techo y el test falla de golpe.

Esto no era verdad antes de escribirlo. `checkSizeBudget` cobraba al camino
streaming 10× el tamaño del archivo —un coste que es real en la API de una
pasada, donde el mensaje vive entero en un `ByteArray`, pero no cuando va por
trozos— y por eso la app rechazaba cualquier archivo de más de unos pocos MB con
un mensaje que además era inútil ("reduce el texto", cuando el problema no era el
texto). Por eso `checkSizeBudget` recibe ahora `ContentCost`: `IN_MEMORY` para las
API de una pasada, `STREAMED` para las que van por trozos.

### Interoperable con Encrypt-C++

El esquema es **byte-a-byte compatible** con
[Encrypt-C++](https://github.com/disruptorh/Encrypt-C-): mismo KDF, mismo pepper
por BLAKE2b, mismo AEAD, mismo sobre JSON/Base64. Un bloque cifrado en la app se
descifra en la herramienta de escritorio y al revés.

Eso no es una promesa, está comprobado contra la biblioteca de C++ de verdad
(`crypto::encrypt` / `crypto::envelope_to_base64`), en los dos sentidos:

| Comprobación | Dónde |
|---|---|
| Con el mismo `salt`/`nonce`/`ciphertext`, Kotlin escribe un sobre **idéntico byte a byte** al de C++ (9 longitudes, incluidos los bordes del Base64: 0, 1, 2, 3, 4 bytes y los perfiles Estándar y Máxima) | `InteropVectorsTest` |
| Kotlin descifra sobres que **`crypto::encrypt` de C++** produjo con Argon2id real, salt y nonce aleatorios, con y sin pepper: texto normal, vacío, UTF-8 con emoji y 300 KB de bytes binarios | `InteropVectorsTest` + `app/src/test/resources/interop/*.blob` |
| El streaming de Kotlin sobre un blob de C++ da el mismo resultado que la API de una pasada | `InteropVectorsTest` |
| Un bit cambiado en un blob de C++ rompe la autenticación; contraseña y pepper equivocados producen **el mismo mensaje** (sin oráculo) | `InteropVectorsTest` |
| **`crypto::decrypt` de C++ descifra lo que escribe Kotlin** (ambos perfiles, con y sin pepper, hasta 500 KB) | `tools/interop/verify.sh` |

Los vectores son datos fijos (`app/src/test/resources/interop/v1..v4.blob`), así
que la compatibilidad queda cubierta por `./gradlew :app:testDebugUnitTest` aunque
el proyecto de escritorio no compile.

### Arquitectura

```text
app/src/main/java/com/reimen/cifra/
  ├─ crypto/          ← Kotlin puro, sin dependencias de Android (testeable con JUnit)
  │   ├─ CryptoEngine.kt           encrypt()/decrypt() y la API streaming
  │   ├─ Envelope.kt               sobre: escritura y parseo incremental
  │   ├─ Base64Url.kt              Base64 URL-safe como flujo
  │   ├─ Argon2Kdf.kt              Argon2id (Bouncy Castle) + binding de pepper
  │   ├─ Blake2b.kt                implementación propia de BLAKE2b
  │   ├─ ChaCha20Core.kt           ChaCha20 (HChaCha20 incluido)
  │   ├─ Poly1305.kt               Poly1305 incremental
  │   ├─ XChaCha20Poly1305.kt      AEAD de una pasada y en streaming
  │   └─ SecureWipe.kt             borrado de ByteArray/CharArray sensibles
  ├─ data/Sources.kt   ← SAF: abrir, tamaño, temporales, publicar
  ├─ ui/
  │   ├─ CryptoViewModel.kt        estado, progreso y cancelación
  │   ├─ MainScreen.kt             pantalla única en Compose
  │   ├─ Plan.kt                   decisiones de la UI, sin Android
  │   └─ Theme.kt                  tema claro/oscuro
  └─ MainActivity.kt   ← FLAG_SECURE + tema
```

`XChaCha20Poly1305` implementa HChaCha20 a mano porque Bouncy Castle no lo
expone: `subkey = HChaCha20(key, nonce[0..16])` y
`nonce2 = 0x00000000 || nonce[16..24]`, igual que
`crypto_aead_xchacha20poly1305_ietf` de libsodium.

## 🔐 Seguridad y firma

### Higiene de datos sensibles

- La capa `crypto/` recibe la contraseña como `CharArray` y la convierte a bytes
  UTF-8 sin crear `String` intermedios; la clave derivada y las copias del pepper
  se sobrescriben con ceros en un `finally`.
- La contraseña y el pepper **no** van a `SavedStateHandle`: ese estado acaba
  escrito en disco cuando Android mata el proceso. Sobreviven a rotar (el
  `ViewModel` sobrevive a los cambios de configuración), no al proceso muerto.
- Al descifrar a archivo, el plaintext va **primero a un temporal** y solo se
  publica cuando el tag ha pasado. Un descifrado con contraseña incorrecta no
  deja un archivo con basura del atacante en el destino.
- Si un cifrado a archivo falla o se cancela, el documento a medias se borra: es
  mejor no dejar nada que dejar algo que parece válido y no lo es.
- `checkSizeBudget()` estima el pico de memoria y rechaza la operación antes de
  que salte un `OutOfMemoryError`, en vez de dejar que el usuario vea un crash.
  El cálculo depende de `ContentCost`: con el mensaje entero en memoria se le
  cobra ×10 (copias en bytes, UTF-16, Base64, JSON y sobre); a trozos solo se le
  cobra el KDF, que es lo único que de verdad ocupa memoria. El error se traduce a
  un mensaje que explica la causa real.
- Un documento cuyo tamaño el proveedor no declara se trata como "desconocido":
  se escribe a archivo en vez de a memoria. El error va en la dirección segura.
- Nada de contraseñas/pepper/plano en logs, crash reports ni backups
  (`allowBackup="false"`, `fullBackupContent="false"` y `dataExtractionRules`
  que excluyen todo, también en Android 12+).
- `FLAG_SECURE`: el contenido no aparece en capturas de pantalla ni en recents.
- El portapapeles se marca como sensible (Android 13+) y el texto copiado se
  borra automáticamente a los 45 segundos, y solo si sigue siendo lo mismo que se
  copió.
- La app **no pide ningún permiso en tiempo de ejecución**. Todo el acceso a
  archivos pasa por el selector del sistema (SAF), así que no hay `INTERNET`, ni
  cámara, ni almacenamiento.

### Qué pasa sin keystore propio

`app/build.gradle.kts` busca un fichero `keystore.properties` **en la raíz del
repo** (se resuelve con `rootProject.file("keystore.properties")`, así que un
clon limpio en cualquier máquina lo encuentra). **Si no está, la variante release
se compila sin firmar**: el APK existe pero `adb install` lo rechaza y al
instalarlo a mano el sistema dice que no se puede instalar. El APK debug no tiene
ese problema (va firmado con la clave de depuración de Android).

Con `minSdk = 26` la firma v1 (la de `META-INF/*.RSA`) no se genera: la v2/v3
vive en el *APK Signing Block*, entre la última entrada local y el directorio
central, y se reconoce por el magic `APK Sig Block 42`. Por eso un APK sin
firmar **no tiene ningún rastro visible** —de ahí que `build_apk.sh` lo compruebe
explícitamente en vez de fiarse de que el build terminó bien.

### Crear un keystore de pruebas

```bash
# 1. Keystore de PRUEBAS: la contraseña está escrita a propósito para que el bloque
#    se pegue tal cual. Es una clave de usar y tirar, no la uses para publicar nada.
keytool -genkeypair -v -keystore release.keystore -storetype PKCS12 -alias cifra -keyalg RSA -keysize 4096 -validity 10000 -storepass test1234 -keypass test1234 -dname "CN=Cifra Test, OU=Dev, O=Local, L=Local, ST=Local, C=ES"

# 2. Apuntar la firma en la raíz del repo
cat > keystore.properties <<'EOF'
storeFile=release.keystore
storePassword=test1234
keyAlias=cifra
keyPassword=test1234
EOF
```

`storeFile` se interpreta **relativo a la raíz del repo**, la misma carpeta donde
está `keystore.properties`: `storeFile=release.keystore` → `./release.keystore`.

Para una clave de verdad: cambia las cuatro líneas de `keystore.properties` por
tus valores antes de publicar. `keyPassword` puede ser la misma que
`storePassword`. Los dos ficheros (`*.keystore` y `keystore.properties`) están en
`.gitignore`, así que no se pueden subir por accidente.

### Comprobar que el APK va firmado

```bash
# 1. Ver el certificado del APK release
find "$HOME/Android/Sdk/build-tools" -name apksigner -type f | sort -V | tail -1 | xargs -I{} {} verify --print-certs app/build/outputs/apk/release/app-release.apk
```

Sobra si usas `build_apk.sh`, que ya lo hace por ti.

### Una comprobación de lint desactivada, y por qué

`FlowOperatorInvokedInComposition` está desactivado en `app/build.gradle.kts`.
No es una concesión por descuido: con AGP 8.9.1 y Kotlin 2.0.20, el detector
revienta el análisis con `InconsistentKotlinMetadataException` al leer el metadata
que escribe el compilador de Kotlin, y el build falla entero. El propio mensaje de
lint dice que es un fallo suyo.

Lo que ese detector vigila es invocar operadores de Flow dentro de una función
@Composable, que es un bug de rendimiento y de recomposición. Aquí no hay nada que
vigilar: el patrón que la pantalla usa es el correcto
(`viewModel.state.collectAsStateWithLifecycle()` en `MainScreen.kt`), los
operadores viven en el ViewModel, y el fallo se disparaba analizando
`CryptoViewModel.kt`, que no contiene ninguna función @Composable. Desactivarlo no
deja nada sin comprobar; arreglarlo de verdad pide subir AGP.

## 📄 Licencia

Apache-2.0 — ver [LICENSE](LICENSE).
