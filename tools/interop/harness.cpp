// Puente de verificación: usa EXACTAMENTE la biblioteca de C++ para cifrar y
// descifrar, sin tocar Kotlin. La app se prueba contra esto en ambos sentidos.
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <cstring>

#include "crypto/crypto_engine.hpp"
#include "crypto/envelope.hpp"
#include "secure_mem/secure_buffer.hpp"
#include <sodium.h>

using secure_mem::byte_buffer;
using secure_mem::secure_string;

static std::string slurp(const char* path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) { std::fprintf(stderr, "no se pudo abrir %s\n", path); std::exit(2); }
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static std::vector<unsigned char> from_hex(const std::string& h) {
  std::vector<unsigned char> v;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    v.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
  }
  return v;
}

// `env <ops> <mem_kib> <salt_hex> <nonce_hex> <ct_hex>` -> Base64 del sobre.
// Con salt y nonce fijos el sobre es determinista, así que sirve para comparar
// la serialización de C++ con la de Kotlin byte a byte.
static std::string envelope_hex(const std::string& ops, const std::string& mem,
                                const std::string& salt_h, const std::string& nonce_h,
                                const std::string& ct_h) {
  crypto::envelope e;
  e.aead_name = crypto::envelope::kAeadName;
  e.kdf_name = crypto::envelope::kKdfName;
  e.ops = std::stoull(ops);
  e.mem_kib = static_cast<std::size_t>(std::stoul(mem));
  const auto salt = from_hex(salt_h);
  const auto nonce = from_hex(nonce_h);
  const auto ct = from_hex(ct_h);
  e.salt = byte_buffer(salt.size());
  std::memcpy(e.salt.data(), salt.data(), salt.size());
  e.nonce = byte_buffer(nonce.size());
  std::memcpy(e.nonce.data(), nonce.data(), nonce.size());
  e.ciphertext = byte_buffer(ct.size());
  std::memcpy(e.ciphertext.data(), ct.data(), ct.size());
  return crypto::envelope_to_base64(e);
}

static void spit(const char* path, const std::string& data) {
  std::ofstream f(path, std::ios::binary);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
}

int main(int argc, char** argv) {
  // `secure_string`/`byte_buffer` usan sodium_malloc/mlock: sin sodium_init()
  // libsodium aborta en la primera asignación.
  if (sodium_init() < 0) {
    std::fprintf(stderr, "sodium_init() fallo\n");
    return 2;
  }
  if (argc >= 6 && std::string(argv[1]) == "env") {
    // env <ops> <mem_kib> <salt_hex> <nonce_hex> <ct_hex>
    std::printf("%s\n", envelope_hex(argv[2], argv[3], argv[4], argv[5], argv[6]).c_str());
    return 0;
  }
  if (argc < 5) {
    std::fprintf(stderr,
                 "uso: harness <enc|dec> <entrada> <salida> <contraseña> [pepper]\n"
                 "     harness env <ops> <mem_kib> <salt_hex> <nonce_hex> <ct_hex>\n");
    return 1;
  }
  const std::string op = argv[1];
  const std::string in = slurp(argv[2]);
  const char* out = argv[3];
  const std::string password = argv[4];
  secure_string pepper;
  if (argc > 5) pepper.assign(argv[5]);

  try {
    if (op == "enc") {
      byte_buffer pt(in.size());
      std::memcpy(pt.data(), in.data(), in.size());
      // Perfil Estándar: 64 MiB, 3 iteraciones (paridad con la app).
      crypto::kdf_profile profile{3, 65536, "Estándar"};
      secure_string pw;
      pw.assign(password.c_str());
      const std::string blob =
          crypto::encrypt(pt, pw, pepper.empty() ? nullptr : &pepper, profile);
      spit(out, blob);
    } else if (op == "dec") {
      secure_string pw;
      pw.assign(password.c_str());
      byte_buffer pt = crypto::decrypt(in, pw, pepper.empty() ? nullptr : &pepper);
      spit(out, std::string(reinterpret_cast<const char*>(pt.data()), pt.size()));
    } else {
      std::fprintf(stderr, "op desconocida: %s\n", op.c_str());
      return 1;
    }
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 3;
  }
  return 0;
}
