#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/android"

echo "Ejecutando tests unitarios (incluye vectores RFC 9106)..."
./gradlew :app:testDebugUnitTest

echo "Compilando APK Release firmado..."
./gradlew :app:assembleRelease

echo "=============================================="
echo "¡Compilación Exitosa!"
echo "APK Generado en: android/app/build/outputs/apk/release/app-release.apk"
echo "=============================================="
