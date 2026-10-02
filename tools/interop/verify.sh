#!/bin/bash
# Verificación de interoperabilidad contra Encrypt-C++, en los dos sentidos.
#
#   1. Un blob que escribe Kotlin lo descifra `crypto::decrypt` de C++.
#   2. Un blob que escribe `crypto::encrypt` de C++ lo descifra Kotlin.
#
# El sentido 2 además está cubierto para siempre por `InteropVectorsTest`, que
# lleva vectores reales de C++ como datos fijos. Este script es para cuando se
# toca el formato y hay que regenerarlos o comprobar en caliente.
#
# Uso:  tools/interop/verify.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CPP="${CPP_ROOT:-/home/reimen/Escritorio/Projects/Encrypt-C++}"
WORK="${TMPDIR:-/tmp}/cifra-interop"

[ -d "$CPP/src" ] || { echo "No encuentro Encrypt-C++ en $CPP (define CPP_ROOT)"; exit 2; }

# La biblioteca de C++ tiene que estar compilada; se avisa en vez de fallar raro.
if [ ! -f "$CPP/build/libencrypt_core.a" ]; then
  echo "Falta $CPP/build/libencrypt_core.a"
  echo "Compílalo con:  cmake -S '$CPP' -B '$CPP/build' && cmake --build '$CPP/build' --target encrypt_core"
  exit 2
fi

mkdir -p "$WORK"
echo "==> Compilando el puente contra la biblioteca de C++"
# -w: los avisos vienen de cabeceras de Encrypt-C++ (kdf_profile no es literal,
# así que sus constexpr no valen) y no de este puente.
c++ -O2 -std=c++17 -w \
  -I"$CPP/src" -isystem "$CPP/build/_deps/libsodium/prefix/include" \
  "$HERE/harness.cpp" -o "$WORK/harness" \
  "$CPP/build/libencrypt_core.a" \
  "$CPP/build/_deps/libsodium/prefix/lib/libsodium.a" -lpthread

# --- 1. Kotlin -> C++ -------------------------------------------------------
# Se reutiliza el test de exportación: deja blobs de Kotlin en $KOTLIN_OUT.
KOTLIN_OUT="$WORK/kotlin"
rm -rf "$KOTLIN_OUT"; mkdir -p "$KOTLIN_OUT"
echo "==> Exportando blobs de Kotlin"
# --rerun-tasks: sin esto Gradle da la tarea por al día y no exporta nada,
# que es justo lo que pasó la primera vez que se ejecutó este script.
./gradlew -q :app:testDebugUnitTest --tests '*InteropExportTest*' \
  -PinteropOut="$KOTLIN_OUT" --rerun-tasks >/dev/null

shopt -s nullglob
exported=("$KOTLIN_OUT"/*.blob)
if [ ${#exported[@]} -eq 0 ]; then
  echo "El test de exportación no produjo ningún blob (¿-PinteropOut llegó al JVM?)"
  exit 1
fi

fail=0
echo "==> C++ descifrando lo que escribió Kotlin"
for blob in "${exported[@]}"; do
  base="${blob%.blob}"
  pw="$(sed -n 1p "$base.meta")"; pepper="$(sed -n 2p "$base.meta")"
  args=("$WORK/harness" dec "$blob" "$base.out" "$pw")
  [ -n "$pepper" ] && args+=("$pepper")
  if "${args[@]}" >/dev/null 2>"$WORK/err.txt" && cmp -s "$base.out" "$base.plain"; then
    echo "    OK   $(basename "$blob")  ($(stat -c%s "$base.plain") B)"
  else
    echo "    FALLO $(basename "$blob"): $(cat "$WORK/err.txt")"; fail=1
  fi
done

# --- 2. C++ -> Kotlin -------------------------------------------------------
echo "==> C++ cifrando, para que lo compruebe InteropVectorsTest"
python3 - "$WORK" <<'PY'
import hashlib, random, subprocess, sys, os
work = sys.argv[1]
random.seed(20260901)
res = os.path.join(work, "cpp")
os.makedirs(res, exist_ok=True)
for name, data, pw, pepper in [
    ("v1", "Hola, mundo\n".encode(), "contraseña/secreta", ""),
    ("v2", b"", "contraseña/secreta", ""),
    ("v3", "Emoji: \U0001F600 \U0001F9EA  ñ 漢\nlínea 2\n".encode(), "clave", "pimienta-secreta"),
    ("v4", bytes(random.getrandbits(8) for _ in range(300_000)), "clave", ""),
]:
    plain = os.path.join(res, name + ".plain")
    open(plain, "wb").write(data)
    subprocess.run([os.path.join(work, "harness"), "enc", plain,
                    os.path.join(res, name + ".blob"), pw] + ([pepper] if pepper else []),
                   check=True)
print("    vectores C++ generados en", res)
PY

echo
[ $fail -eq 0 ] && echo "INTEROP BIDIRECCIONAL OK" || { echo "HAY FALLOS"; exit 1; }
