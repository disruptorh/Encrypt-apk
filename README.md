# Cifra

App Android (Kotlin + Jetpack Compose) de cifrado de texto con un único
esquema: **XChaCha20-Poly1305 + Argon2id**. 100% offline, sin red, sin backend,
sin telemetría.

![Licencia](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)

## Uso

1. **Cifrar**: escribe el texto, una contraseña (obligatoria) y opcionalmente un
   "campo secreto adicional" (pepper). Elige el perfil del KDF y pulsa
   **CIFRAR**. Obtienes un único bloque Base64 URL-safe.
2. **Descifrar**: pega el bloque, la misma contraseña y el mismo pepper si lo
   usaste. Pulsa **DESCIFRAR**.

El sobre lleva dentro los parámetros del KDF, así que un bloque cifrado con el
perfil Estándar se puede descifrar aunque el perfil por defecto cambie. No hace
falta recordar qué perfil se usó.

## Decisiones de diseño

| Componente | Elección |
|---|---|
| Cifrado | XChaCha20-Poly1305 (IETF, tag de 16 bytes) — `aead: xchacha20poly1305_ietf` |
| KDF | Argon2id v1.3 (RFC 9106) con **parallelism = 1** |
| Pepper | No va al KDF: se enlaza después con **BLAKE2b keyed** (paridad con libsodium) |
| Salt | 16 bytes `SecureRandom` por cifrado |
| Nonce | 24 bytes `SecureRandom` por cifrado (XChaCha20 admite reutilización con menos riesgo que ChaCha20) |
| AAD | Los parámetros del KDF (`v`, `aead`, `kdf`, `ops`, `mem_kib`) van autenticados **dentro del tag**: un ataque que los altere rompe la verificación |
| Formato | JSON (`v, aead, kdf, ops, mem_kib, salt, nonce, ciphertext`) → Base64 URL-safe sin padding |
| Serialización | A mano con `StringBuilder`, con lista blanca de campos (`ALLOWED_FIELDS`): rechaza JSON con claves extra |

### Perfiles de fuerza

| Perfil | Memoria | Iteraciones |
|---|---|---|
| Estándar | 64 MiB (65536 KiB) | 3 |
| Máxima | 256 MiB (262144 KiB) | 6 |

`parallelism` no viaja en el sobre porque está fijado a `1` en ambos lados: es
lo que exige libsodium para ser interoperable.

## Interoperable con Encrypt-C++

El esquema es **byte-a-byte compatible** con
[Encrypt-C++](../Encrypt-C++/README.md): mismo KDF, mismo pepper por BLAKE2b,
mismo AEAD, mismo sobre JSON/Base64. Un bloque cifrado en la app se descifra en
la herramienta de escritorio y al revés.

## Arquitectura

```
app/src/main/java/com/reimen/cifra/
  ├─ crypto/          ← Kotlin puro, sin dependencias de Android (100% testeable con JUnit)
  │   ├─ CryptoEngine.kt           encrypt()/decrypt(), única puerta de entrada
  │   ├─ Argon2Kdf.kt              Argon2id (Bouncy Castle) + binding de pepper
  │   ├─ Blake2b.kt                implementación propia de BLAKE2b
  │   ├─ XChaCha20Poly1305.kt      HChaCha20 propio + AEAD de Bouncy Castle
  │   ├─ Envelope.kt               serialización/parseo del sobre
  │   └─ SecureWipe.kt             borrado de ByteArray/CharArray sensibles
  ├─ ui/MainScreen.kt  ← pantalla única en Jetpack Compose
  └─ MainActivity.kt   ← FLAG_SECURE (sin capturas de pantalla)
```

`XChaCha20Poly1305` implementa HChaCha20 a mano porque Bouncy Castle no lo
expone: `subkey = HChaCha20(key, nonce[0..16])` y
`nonce2 = 0x00000000 || nonce[16..24]`, igual que
`crypto_aead_xchacha20poly1305_ietf` de libsodium.

## Higiene de datos sensibles

- La capa `crypto/` recibe la contraseña como `CharArray` y la convierte a bytes
  UTF-8 sin crear `String` intermedios; la clave derivada y las copias del pepper
  se sobrescriben con ceros en un `finally`.
- Se llama a `Runtime.gc()` explícitamente tras derivar la clave para liberar los
  bloques de Argon2 **antes** de reservar el ciphertext, en vez de sumar ambos
  picos de memoria.
- `checkSizeBudget()` estima el pico de memoria (KDF + 10× el texto por las
  copias en bytes, UTF-16, Base64 y JSON + 48 MiB de base) y rechaza la operación
  antes de que salte un `OutOfMemoryError`; el error se traduce a un mensaje
  legible.
- Nada de contraseñas/pepper/plano en logs, crash reports ni backups
  (`android:allowBackup="false"`, `android:fullBackupContent="false"`).
- `FLAG_SECURE`: el contenido no aparece en capturas de pantalla ni en recents.
- El portapapeles se marca como sensible (Android 13+) y el texto copiado se
  borra automáticamente a los 45 segundos.

## Requisitos y build

- Android SDK 26+ (`minSdk 26`), `targetSdk 34`
- JDK 17, Gradle vía wrapper
- Dependencias: Compose BOM 2024.06.00, `bcprov-jdk18on:1.78.1`
- `android:largeHeap="true"` — necesario para el perfil de 256 MiB

```bash
./gradlew :app:testDebugUnitTest   # tests
./gradlew :app:assembleRelease     # APK
```

## Tests

`./gradlew :app:testDebugUnitTest` — **53 tests**:

| Fichero | Tests | Cubre |
|---|---|---|
| `Argon2KdfTest.kt` | 13 | Vector oficial de **Argon2id RFC 9106** (Apéndice A.3), binding de pepper, rangos fuera de límite |
| `CryptoEngineTest.kt` | 21 | Round-trip: texto vacío, 1 char, 10 KB, emojis/UTF-8, con/sin pepper. Negativos: contraseña incorrecta, pepper incorrecto, ciphertext corrupto. Presupuesto de memoria |
| `EnvelopeTest.kt` | 13 | Fuzzing del parser: JSON malformado, Base64 inválido, campos ausentes, claves no permitidas, parámetros fuera de rango |
| `XChaCha20Poly1305Test.kt` | 6 | Vectors de HChaCha20 y AEAD, nonce de 24 bytes, tag truncado |

## ⚠️ `build_apk.sh` está roto

El script hace `cd "$DIR/android"`, pero **no existe ningún subdirectorio
`android/`**: la raíz del repositorio ya *es* el proyecto Gradle. El script falla
con `No such file or directory`. Lánzalo así mientras tanto:

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleRelease
# → app/build/outputs/apk/release/app-release.apk  (firmado, ofuscado con R8)
```

## Licencia

Apache-2.0 — ver [LICENSE](LICENSE).
