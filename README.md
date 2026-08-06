# Cifra

App Android (Kotlin + Jetpack Compose) de cifrado con **un único esquema**:
**AES-256-GCM + Argon2id**. 100% offline, sin red, sin backend, sin telemetría.

## Uso

1. **Cifrar**: escribe el texto, una contraseña (obligatoria) y opcionalmente un
   "campo secreto adicional" (pepper). Pulsa **CIFRAR**. Obtienes un único bloque
   Base64 URL-safe.
2. **Descifrar**: pega el bloque, la misma contraseña y el mismo pepper si lo
   usaste. Pulsa **DESCIFRAR**.

## Decisiones de diseño (resumen)

| Componente | Elección |
|---|---|
| Cifrado | AES-256-GCM (autenticado, tag de 16 bytes) |
| KDF | Argon2id (RFC 9106), perfil Estándar 64 MiB/3 iters o Máxima 256 MiB/6 iters |
| Salt | 16 bytes `SecureRandom` por cifrado |
| Nonce | 12 bytes `SecureRandom` por cifrado |
| Pepper | Se pasa como `secret` de Argon2id; **nunca se serializa ni persiste** |
| Formato | JSON (`v, kdf, mem_kib, iters, parallelism, salt, nonce, ciphertext`) → Base64 URL-safe sin padding |
| Parámetros KDF | Viajan dentro del sobre → compatibilidad al subir la fuerza |

## Arquitectura

```
app/src/main/java/com/reimen/cifra/
  ├─ crypto/          ← Kotlin puro, sin dependencias de Android (100% testeable con JUnit)
  │   ├─ CryptoEngine.kt   encrypt()/decrypt(), única puerta de entrada
  │   ├─ Argon2Kdf.kt      wrapper sobre Bouncy Castle Argon2id
  │   ├─ AesGcmCipher.kt   wrapper sobre javax.crypto AES/GCM/NoPadding
  │   ├─ Envelope.kt       serialización/deserialización del sobre
  │   └─ SecureWipe.kt     borrado de ByteArray/CharArray sensibles
  ├─ ui/MainScreen.kt ← pantalla única en Jetpack Compose
  └─ MainActivity.kt  ← FLAG_SECURE (sin capturas de pantalla)
```

## Higiene de datos sensibles

- La capa `crypto/` recibe la contraseña como `CharArray` y la convierte a bytes
  UTF-8 sin crear `String` intermedios; la clave derivada y las copias del pepper
  se sobrescriben con ceros tras cada operación.
- Nada de contraseñas/pepper/plano en logs, crash reports ni backups
  (`android:allowBackup="false"`).
- `FLAG_SECURE`: el contenido no aparece en capturas de pantalla ni en recents.
- El portapapeles se marca como sensible (Android 13+) y el texto copiado se
  borra automáticamente a los 45 segundos.

## Tests

`./gradlew :app:testDebugUnitTest` — 31 tests:

- Vector de prueba oficial de **Argon2id RFC 9106** (Apéndice A.3).
- Round-trip: texto vacío, 1 char, 10 KB, emojis/UTF-8, con/sin pepper.
- Negativos: contraseña incorrecta, pepper incorrecto, ciphertext corrupto.
- Fuzzing del parser del sobre: JSON malformado, Base64 inválido, campos
  ausentes, parámetros fuera de rango.

## Release

```
./build_apk.sh
```

Genera `android/app/build/outputs/apk/release/app-release.apk`, firmado con el
keystore release del entorno y ofuscado con R8.
