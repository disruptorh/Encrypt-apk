#!/bin/bash
# Compila el APK release y comprueba que sale firmado.
#
# La raíz del repositorio ES el proyecto Gradle: no hay subdirectorio
# `android/`, así que no se hace ningún `cd`.
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

APK="app/build/outputs/apk/release/app-release.apk"

echo "Ejecutando tests unitarios (incluye vectores RFC 9106)..."
./gradlew :app:testDebugUnitTest

echo "Compilando APK Release..."
./gradlew :app:assembleRelease

# ---------------------------------------------------------------------------
# Verificación de la firma.
#
# Importa más de lo que parece: con `minSdk = 26` la firma v1 no se genera, así
# que un APK sin firmar NO tiene ningún `META-INF/*.RSA` y el error visible es
# simplemente "no se puede instalar". Un despliegue a medias que asumía que sí
# estaba firmado es el peor sitio para descubrirlo.
#
# La firma v2/v3 vive en el "APK Signing Block", entre la última entrada local y
# el directorio central, y se reconoce por el magic `APK Sig Block 42`.
# ---------------------------------------------------------------------------
echo "Comprobando la firma del APK..."

if [ ! -f "$APK" ]; then
    echo "ERROR: no se encontró $APK" >&2
    exit 1
fi

if ! LC_ALL=C grep -qa "APK Sig Block 42" "$APK"; then
    echo "ERROR: el APK NO está firmado (no tiene bloque de firma v2/v3)." >&2
    echo "       Sin keystore.properties el release sale sin firmar a propósito," >&2
    echo "       pero si esperabas un APK instalable, esto es lo que hay que arreglar." >&2
    exit 1
fi

# Si hay un apksigner en el SDK, se usa para dar el detalle del certificado.
SDK_DIR="$(sed -n 's/^sdk\.dir=//p' local.properties 2>/dev/null || true)"
if [ -n "${SDK_DIR:-}" ] && [ -d "$SDK_DIR/build-tools" ]; then
    APKSIGNER="$(find "$SDK_DIR/build-tools" -name apksigner -type f 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "${APKSIGNER:-}" ]; then
        "$APKSIGNER" verify --print-certs "$APK" || {
            echo "ERROR: apksigner no da el APK por válido." >&2
            exit 1
        }
    fi
fi

echo "=============================================="
echo "Compilación exitosa"
echo "APK firmado en: $APK"
echo "=============================================="