package com.reimen.cifra.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Interoperabilidad real con Encrypt-C++, verificada contra la biblioteca de C++
 * y no contra una copia de los vectores.
 *
 * Los dos sentidos_importantes están cubiertos:
 *
 *  1. **Serialización, byte a byte.** Con el mismo `salt`, `nonce` y
 *     `ciphertext`, el sobre que escribe Kotlin tiene que ser *idéntico* al que
 *     escribe `envelope_to_base64` de C++. Esto es lo que fija el orden de los
 *     campos, la ausencia de padding y el modo en que se cierra el objeto.
 *  2. **Cifrado y descifrado de verdad.** Los blobs de `resources/interop` los
 *     generó `crypto::encrypt` de C++ con Argon2id real, salt y nonce aleatorios
 *     y pepper opcional. Kotlin tiene que sacar de ellos exactamente el mismo
 *     plaintext, lo que implica que Argon2id, el binding del pepper, el AAD y el
 *     AEAD coinciden de verdad.
 *
 * Los vectores se generaron con `crypto::encrypt` / `crypto::envelope_to_base64`
 * de Encrypt-C++ y se guardaron aquí como datos fijos. No hace falta C++ para
 * ejecutar los tests: la compatibilidad queda cubierta para siempre aunque la
 * otra mitad del proyecto no se pueda compilar.
 */
class InteropVectorsTest {

    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private fun sha256(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    private fun resource(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream("interop/$name")?.use { it.readBytes() }
            ?: throw AssertionError("falta el recurso interop/$name")

    /** El blob tal como lo consume [CryptoEngine.decrypt]: Base64 en un String. */
    private fun blobOf(name: String): String = resource(name).toString(Charsets.US_ASCII).trim()

    /** Sobre con `salt`/`nonce` fijos: la salida tiene que ser determinista. */
    private class Vector(
        val ops: Int,
        val memKib: Int,
        val salt: String,
        val nonce: String,
        val ciphertext: String,
        val expected: String
    )

    /** Blob producido por `crypto::encrypt` de C++ con datos aleatorios. */
    private class Real(
        val name: String,
        val password: String,
        val pepper: String?,
        val plaintextBytes: Int,
        val plaintextSha256: String
    )

    @Test
    fun `kotlin writes byte-identical envelopes to C++`() {
        val vectors = listOf(
        Vector(
            ops = 2,
            memKib = 64,
            salt = "cd7505d581b9ad894f4a9851c82cd665",
            nonce = "5546185f57d840946f5d619e32199cb17900c0b5128ff4fc",
            ciphertext = "",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6InpYVUYxWUc1cllsUFNwaFJ5Q3pXWlEiLCJub25jZSI6IlZVWVlYMWZZUUpSdlhXR2VNaG1jc1hrQXdMVVNqX1Q4IiwiY2lwaGVydGV4dCI6IiJ9"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "6ce3cc619cfac9011372b3d8009a8bde",
            nonce = "8c14816272e5e458a344cb42ad6a354a1c48f1d9e7231b66",
            ciphertext = "74",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6ImJPUE1ZWno2eVFFVGNyUFlBSnFMM2ciLCJub25jZSI6ImpCU0JZbkxsNUZpalJNdENyV28xU2h4SThkbm5JeHRtIiwiY2lwaGVydGV4dCI6ImRBIn0"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "c9f31505e06a2743bef06efb644142d7",
            nonce = "fcd6bf9c23e0613a8da4354983a5e074484bb1fc5770ea40",
            ciphertext = "f8e2",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6InlmTVZCZUJxSjBPLThHNzdaRUZDMXciLCJub25jZSI6Il9OYV9uQ1BnWVRxTnBEVkpnNlhnZEVoTHNmeFhjT3BBIiwiY2lwaGVydGV4dCI6Ii1PSSJ9"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "9d14304c49a4b7ad7cd0bdac0e85e0c9",
            nonce = "c65362a7a749f79c3c9699284e6242d22fa1e479668fcaa8",
            ciphertext = "4dc185",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6Im5SUXdURW1rdDYxODBMMnNEb1hneVEiLCJub25jZSI6InhsTmlwNmRKOTV3OGxwa29UbUpDMGktaDVIbG1qOHFvIiwiY2lwaGVydGV4dCI6IlRjR0YifQ"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "d1d662fc8ffdde3c0e3b9516b9d0567c",
            nonce = "1c794a1a85cb1879957261ae4462e63d2b70758b7c75adbf",
            ciphertext = "05a962d0",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6IjBkWmlfSV85M2p3T081VVd1ZEJXZkEiLCJub25jZSI6IkhIbEtHb1hMR0htVmNtR3VSR0xtUFN0d2RZdDhkYTJfIiwiY2lwaGVydGV4dCI6IkJhbGkwQSJ9"
        ),
        Vector(
            ops = 3,
            memKib = 262144,
            salt = "218a0ce798c85c152305e03841787f46",
            nonce = "403340672952b5ace5d3c558173938fab62535f38fe36a35",
            ciphertext = "62a0fef76f4fa24efbd699ca53ee0873",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjozLCJtZW1fa2liIjoyNjIxNDQsInNhbHQiOiJJWW9NNTVqSVhCVWpCZUE0UVhoX1JnIiwibm9uY2UiOiJRRE5BWnlsU3RhemwwOFZZRnprNC1yWWxOZk9QNDJvMSIsImNpcGhlcnRleHQiOiJZcUQtOTI5UG9rNzcxcG5LVS00SWN3In0"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "1604a25fe9e778c3559dacd34f3ff18b",
            nonce = "95b12c081544fbe3da1113e1868c54a7957c2cc10c7ade0f",
            ciphertext = "edae26206d3b3729b19b445c623598fca8be465fe26328f0d5cf8909154b689bc95f577a4cde9b6ec9f6563b12d2c6d7bab811f8bde7c4d0cddaa13275d5cf3bdff42c1e64038133c93b41f4c191c122c1ef62f44716e5b6bc7c588df8178ab7b1d685c4b6a22be92c3c6c171cc97fcce19f755bb640b4516b6b583a11ef28920167fc319fd1b811b7434f3d1b2db81a7c1d5803eb8af5f89c6381d282fd19ecd330faf257d1f87af038258bf48ac07f1b96811ddc96ee11f369955010d8a6ca7e340904b459dab4f1d272103692c8eebe649a0a127b6c1cf3aac2f30a70405ea09b7c85e693737daf50522256369ec28d83bef172f13471ac7230f9c13388a8",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6IkZnU2lYLW5uZU1OVm5helRUel94aXciLCJub25jZSI6ImxiRXNDQlZFLS1QYUVSUGhob3hVcDVWOExNRU1ldDRQIiwiY2lwaGVydGV4dCI6IjdhNG1JRzA3TnlteG0wUmNZaldZX0tpLVJsX2lZeWp3MWMtSkNSVkxhSnZKWDFkNlRONmJic24yVmpzUzBzYlh1cmdSLUwzbnhORE4ycUV5ZGRYUE85XzBMQjVrQTRFenlUdEI5TUdSd1NMQjcyTDBSeGJsdHJ4OFdJMzRGNHEzc2RhRnhMYWlLLWtzUEd3WEhNbF96T0dmZFZ1MlFMUlJhMnRZT2hIdktKSUJaX3d4bjlHNEViZERUejBiTGJnYWZCMVlBLXVLOWZpY1k0SFNndjBaN05Ndy12SlgwZmg2OERnbGlfU0t3SDhibG9FZDNKYnVFZk5wbFZBUTJLYktmalFKQkxSWjJyVHgwbklRTnBMSTdyNWttZ29TZTJ3Yzg2ckM4d3B3UUY2Z20zeUY1cE56ZmE5UVVpSldOcDdDallPLThYTHhOSEdzY2pENXdUT0lxQSJ9"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "3ee1b131d539beedd8b06f72ea9a0956",
            nonce = "fa6d631de76c9dd6bad47041ad493f683230b57663af1fb0",
            ciphertext = "3c1e8246da73218b9336cdbcf3436a14feab963400eb7e938e68d55147a954c15dc855cb114e4d4ec50330fca9b8dbe94eddc65f2997a4b50aa8aae675b374de4aa4bf0bc7f0e9bed383bd1cf422967f55370fb201e863d7a35e67bd5a5a73605b5cfe57ba230310f1b73f3aa61fa1f2501a02320ae745ce0358dc6a11b0d414858aca3e2c66e691c5572d4bfb719cf44663c3030fa0dd184a268aedc6f6a59de927aed0b13dce0375d6e0faebc13b8bed6e7c0cd1c3d1843ce50345e2c7caba62478e73a8fe753579fbe2a016bec53304bb354bdd23c1a2b9f6b30dcf464c8829d5ef5fa2084f295fa32fcc8bef6a0a9fa3190874a9a94056ccb07a878aa3bbb1",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6IlB1R3hNZFU1dnUzWXNHOXk2cG9KVmciLCJub25jZSI6Ii1tMWpIZWRzbmRhNjFIQkJyVWtfYURJd3RYWmpyeC13IiwiY2lwaGVydGV4dCI6IlBCNkNSdHB6SVl1VE5zMjg4ME5xRlA2cmxqUUE2MzZUam1qVlVVZXBWTUZkeUZYTEVVNU5Uc1VETVB5cHVOdnBUdDNHWHltWHBMVUtxS3JtZGJOMDNrcWt2d3ZIOE9tLTA0TzlIUFFpbG45Vk53LXlBZWhqMTZOZVo3MWFXbk5nVzF6LVY3b2pBeER4dHo4NnBoLWg4bEFhQWpJSzUwWE9BMWpjYWhHdzFCU0Zpc28tTEdibWtjVlhMVXY3Y1p6MFJtUERBdy1nM1JoS0pvcnR4dmFsbmVrbnJ0Q3hQYzREZGRiZy11dkJPNHZ0Ym53TTBjUFJoRHpsQTBYaXg4cTZZa2VPYzZqLWRUVjUtLUtnRnI3Rk13UzdOVXZkSThHaXVmYXpEYzlHVElncDFlOWZvZ2hQS1Ytakw4eUw3Mm9LbjZNWkNIU3BxVUJXekxCNmg0cWp1N0UifQ"
        ),
        Vector(
            ops = 2,
            memKib = 64,
            salt = "f20568c2af05a48a87a7009c17ea3489",
            nonce = "76181713ebb7f2767976d8a20833112c753c83e119440a20",
            ciphertext = "9f6d15392beabc518be1b210d2e3b54864d5253b24d1fcb69cdf572979d25c4228e18834ea86275a94045d3a365ec7d6996b549cb0cb1510b34378a8d56541a312915bd97952506e7db931dbe23fcf968edcb3afb4163549682259de0b082debc875c9f7328ed07978d0ff833a5c5bd0c6c365c26553f448f5b3073904a8fb403ef0b9d52f44596c35661d8fbe3e9ad89b3728794f45aee9002be510d45158bb48cc10fb8e16356b9eaef5a5c9d82c0896b81487f6d0b3e89dad61cf2597ac72b4e17cc38af1e933318e1a2e296fcd678f66230ecb3bdc66d68e99561500ae21910721914df8afb8458a7bf5ca5236b8b7c34e6eb74cef0aa7541cc87def0849d13b11dc228c297575b18448dd5b913af24c14059691bb4c108cbb975506102c5b068145fe071d250f05dc2bac1bb891958fd8a86189a6ce5574e3fb402d566a5ec87faa900828fbcd0113faa7de3f432c1f29f8a9c164267499659ab81f4015fa2ce272b0031ccae55388840bbebbb32892edf5770aadcf638309cca19d80208c1c5ffc5cf5355aef396fed6612b90628cd546013ed616a1ba87b56358b19a169b55e324d2d1878201dd238095570a37f8e7e757395851e46a71dcd9e2f4ff07b06f14c2ef0fd0f26dc2d3950397a3050f2a01755f766504185b677e9ddb3835d29b4e3b9c5f68630acc2382b6c3cc32f253d4509e1f4f83211f21621d62d5ff9c543b5011ef0cf928d41546cbff782985263af547c417a590c3e0b76c19c92457adaaa516f72f0e2d1cef2ea545c665b6fa762c5c23bd4f7669c4c10bc106889c0aeec3d2592dc012cbd79edd77d1cc7c3279e24a27f48cce4de1b57eec5205369bc22d3b93e6bf7cc684a579dbf3007089f566a0b54a82a8d034b0c1b902417859e56da0871380335bb04957b16571c1fbc4dc1498536d5b39c81dd680dd21da41228cf26e480cf62e94e8b97c3f897042b71495dec434986cde88b4aadb7afdd5797f254c8df1ec015ce7787c4a4ddb5afd35c790e438cc828e6bca083b434acd430ef0c643e5643ebd0b658e6e0cad9616f468ffe332c8fdc6f066af672d5fdd1f8a71186beeb317352388dc5c9433b5a16ee4018c36c5039c3f403904a357cde9119e560a96fabfe2ecd80e3d59646bbac7a0b37b5326c44a933c714ba2e0ac86fee07ed56b7cf3e91f957fd17088245eb57b0ccb06d612d077961d5c1ac7f8d7694ce63d865fb4873b38574d6072291f795dc010e21f976d488f85b411b3c990b0fb9bb52d9d3ee2bc5caec7b6d5113a58ee6c1be989bd2d134110d5dc08864aefd5d9276fc81b3f659d5fdce233eb7ad63bb34597ae39e93b88114742b8df8d89ae0a3a2869a7546aab31e52324a7672f1a912be9bac79db23eae1cb53ab771e17c2eb40",
            expected = "eyJ2IjoxLCJhZWFkIjoieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsImtkZiI6ImFyZ29uMmlkIiwib3BzIjoyLCJtZW1fa2liIjo2NCwic2FsdCI6IjhnVm93cThGcElxSHB3Q2NGLW8waVEiLCJub25jZSI6ImRoZ1hFLXUzOG5aNWR0aWlDRE1STEhVOGctRVpSQW9nIiwiY2lwaGVydGV4dCI6Im4yMFZPU3ZxdkZHTDRiSVEwdU8xU0dUVkpUc2swZnkybk45WEtYblNYRUlvNFlnMDZvWW5XcFFFWFRvMlhzZldtV3RVbkxETEZSQ3pRM2lvMVdWQm94S1JXOWw1VWxCdWZia3gyLUlfejVhTzNMT3Z0QlkxU1dnaVdkNExDQzNyeUhYSjl6S08wSGw0MFAtRE9seGIwTWJEWmNKbFVfUkk5Yk1IT1FTby0wQS04TG5WTDBSWmJEVm1IWS0tUHByWW16Y29lVTlGcnVrQUstVVExRkZZdTBqTUVQdU9GalZybnE3MXBjbllMQWlXdUJTSDl0Q3o2SjJ0WWM4bGw2eHl0T0Y4dzRyeDZUTXhqaG91S1dfTlo0OW1JdzdMTzl4bTFvNlpWaFVBcmlHUkJ5R1JUZml2dUVXS2VfWEtVamE0dDhOT2JyZE03d3FuVkJ6SWZlOElTZEU3RWR3aWpDbDFkYkdFU04xYmtUcnlUQlFGbHBHN1RCQ011NWRWQmhBc1d3YUJSZjRISFNVUEJkd3JyQnU0a1pXUDJLaGhpYWJPVlhUai0wQXRWbXBleUgtcWtBZ28tODBCRV9xbjNqOURMQjhwLUtuQlpDWjBtV1dhdUI5QUZmb3M0bkt3QXh6SzVWT0loQXUtdTdNb2t1MzFkd3F0ejJPRENjeWhuWUFnakJ4Zl9GejFOVnJ2T1dfdFpoSzVCaWpOVkdBVDdXRnFHNmg3VmpXTEdhRnB0VjR5VFMwWWVDQWQwamdKVlhDamY0NS1kWE9WaFI1R3B4M05uaTlQOEhzRzhVd3U4UDBQSnR3dE9WQTVlakJROHFBWFZmZG1VRUdGdG5mcDNiT0RYU20wNDduRjlvWXdyTUk0SzJ3OHd5OGxQVVVKNGZUNE1oSHlGaUhXTFZfNXhVTzFBUjd3ejVLTlFWUnN2X2VDbUZKanIxUjhRWHBaREQ0TGRzR2Nra1Y2MnFwUmIzTHc0dEhPOHVwVVhHWmJiNmRpeGNJNzFQZG1uRXdRdkJCb2ljQ3U3RDBsa3R3QkxMMTU3ZGQ5SE1mREo1NGtvbjlJek9UZUcxZnV4U0JUYWJ3aTA3ay1hX2ZNYUVwWG5iOHdCd2lmVm1vTFZLZ3FqUU5MREJ1UUpCZUZubGJhQ0hFNEF6VzdCSlY3RmxjY0g3eE53VW1GTnRXem5JSGRhQTNTSGFRU0tNOG01SURQWXVsT2k1ZkQtSmNFSzNGSlhleERTWWJONkl0S3JiZXYzVmVYOGxUSTN4N0FGYzUzaDhTazNiV3YwMXg1RGtPTXlDam12S0NEdERTczFERHZER1EtVmtQcjBMWlk1dURLMldGdlJvXy1NeXlQM0c4R2F2WnkxZjNSLUtjUmhyN3JNWE5TT0kzRnlVTTdXaGJ1UUJqRGJGQTV3X1FEa0VvMWZONlJHZVZncVctcl9pN05nT1BWbGthN3JIb0xON1V5YkVTcE04Y1V1aTRLeUdfdUItMVd0ODgta2ZsWF9SY0lna1hyVjdETXNHMWhMUWQ1WWRYQnJILU5kcFRPWTlobC0waHpzNFYwMWdjaWtmZVYzQUVPSWZsMjFJajRXMEViUEprTEQ3bTdVdG5UN2l2Rnl1eDdiVkVUcFk3bXdiNlltOUxSTkJFTlhjQ0laSzc5WFpKMl9JR3o5bG5WX2M0alByZXRZN3MwV1hyam5wTzRnUlIwSzQzNDJKcmdvNktHbW5WR3FyTWVVakpLZG5MeHFSSy1tNng1MnlQcTRjdFRxM2NlRjhMclFBIn0"
        )
        )
        vectors.forEach { v ->
            val out = ByteArrayOutputStream()
            EnvelopeWriter.new(out, v.ops, v.memKib, hex(v.salt), hex(v.nonce)).use { w ->
                val ct = hex(v.ciphertext)
                if (ct.isNotEmpty()) w.write(ct, 0, ct.size)
            }
            val mine = out.toString(Charsets.US_ASCII)
            assertEquals(
                "el sobre debe ser idéntico al de C++ (ops=${v.ops}, mem=${v.memKib}, ct=${v.ciphertext.length / 2} B)",
                v.expected,
                mine
            )
        }
    }

    @Test
    fun `kotlin decrypts blobs produced by C++`() {
        val cases = listOf(
        Real(
            name = "v1",
            password = "contraseña/secreta",
            pepper = null,
            plaintextBytes = 12,
            plaintextSha256 = "646a52c70598f74025b6e27c6278a7a66e00008b3d27e11c8dd82c88aba1f61b"
        ),
        Real(
            name = "v2",
            password = "contraseña/secreta",
            pepper = null,
            plaintextBytes = 0,
            plaintextSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        Real(
            name = "v3",
            password = "clave",
            pepper = "pimienta-secreta",
            plaintextBytes = 34,
            plaintextSha256 = "91df90ea6c0d87fe4d0f36b9c5247d8e0afdb1aab26eadf6f7c46ac3074a0cd7"
        ),
        Real(
            name = "v4",
            password = "clave",
            pepper = null,
            plaintextBytes = 300000,
            plaintextSha256 = "46250e8e8dadf1c8d99534e4e40d4d99bb674c9c6f988b64e7a14e66d7008e5c"
        )
        )
        cases.forEach { c ->
            val blob = resource("${c.name}.blob")
            val plain = CryptoEngine.decrypt(
                blobOf("${c.name}.blob"),
                c.password.toCharArray(),
                c.pepper?.toCharArray()
            )
            assertEquals("${c.name}: tamaño del plaintext", c.plaintextBytes, plain.size)
            assertEquals("${c.name}: el plaintext no coincide", c.plaintextSha256, sha256(plain))
        }
    }

    @Test
    fun `streaming decrypt of a C++ blob equals the in-memory decrypt`() {
        val blob = resource("v4.blob")
        val oneShot = CryptoEngine.decrypt(blobOf("v4.blob"), "clave".toCharArray(), null)
        val streamed = ByteArrayOutputStream()
        CryptoEngine.startDecrypting(blob.size.toLong(), { ByteArrayInputStream(blob) }, "clave".toCharArray(), null)
            .use { dec -> dec.decrypt { b, off, len -> streamed.write(b, off, len) } }
        assertArrayEquals(oneShot, streamed.toByteArray())
        assertEquals(300_000, oneShot.size)
    }

    @Test
    fun `C++ blobs are rejected with the wrong password or pepper`() {
        val blob = blobOf("v3.blob")
        val bad = arrayOf<Pair<CharArray, CharArray?>>(
            "clave".toCharArray() to null,                               // sin pepper
            "clave".toCharArray() to "otro-pepper".toCharArray(),
            "otra-clave".toCharArray() to "pimienta-secreta".toCharArray()
        )
        val messages = bad.map { (pw, pepper) ->
            val e = assertThrows(CryptoEngine.CryptoException::class.java) {
                CryptoEngine.decrypt(blob, pw, pepper)
            }
            e.message
        }
        // Los tres fallos tienen que producir el MISMO mensaje. Distinguir
        // "contraseña mala" de "pepper malo" de "blob manipulado" le daría a un
        // atacante un oráculo gratis sobre qué parte del secreto falló.
        assertTrue("mensajes divergentes: $messages", messages.distinct().size == 1)
        messages.first()!!.let { m ->
            assertTrue("mensaje vacío", m.isNotBlank())
            // No puede filtrar detalles internos (nombres de clases de excepción,
            // nombres de primitivas), que es lo que delata la implementación.
            listOf("Exception", "poly1305", "chacha", "argon2", "javax.crypto")
                .forEach { assertTrue("filtra detalles internos: $m", !m.contains(it, ignoreCase = true)) }
        }
    }

    @Test
    fun `a single flipped bit in a C++ blob breaks authentication`() {
        val blob = resource("v1.blob").copyOf()
        // Se toca el centro del Base64 exterior: eso cae dentro del ciphertext.
        val i = blob.size / 2
        blob[i] = if (blob[i] == 'A'.code.toByte()) 'B'.code.toByte() else 'A'.code.toByte()
        assertThrows(CryptoEngine.CryptoException::class.java) {
            CryptoEngine.decrypt(
                blob.toString(Charsets.US_ASCII),
                "contraseña/secreta".toCharArray(),
                null
            )
        }
    }

    @Test
    fun `the header C++ writes is understood field by field`() {
        val blob = resource("v3.blob")
        val header = EnvelopeReader.readHeader(blob.size.toLong()) { ByteArrayInputStream(blob) }
        assertEquals(1, header.version)
        assertEquals(Envelope.AEAD_NAME, header.aead)
        assertEquals(Envelope.KDF_NAME, header.kdf)
        assertEquals(3, header.ops)
        assertEquals(65536, header.memKib)
        assertTrue("el header debe localizar el campo ciphertext", header.ciphertextChars > 0)

        // Y debe coincidir con lo que dice el parser de una pasada.
        val json = Base64Url.decode(String(blob, Charsets.US_ASCII).trim())
        val parsed = EnvelopeReader.parseHeader(json)
        assertArrayEquals("salt", parsed.salt, header.salt)
        assertArrayEquals("nonce", parsed.nonce, header.nonce)
        assertEquals("inicio del ciphertext", parsed.ciphertextStartInJson, header.ciphertextStartInJson)
        // `readHeader` solo conoce la longitud del blob, así que su longitud es una
        // cota superior con un par de bytes de margen; `parseHeader` es exacto.
        // Lo que no puede pasar es que la cota se quede corta.
        assertTrue(
            "readHeader dio una cota por debajo del valor exacto: " +
                "${header.ciphertextChars} < ${parsed.ciphertextChars}",
            header.ciphertextChars >= parsed.ciphertextChars
        )
        assertTrue(
            "margen mayor que el documentado: ${header.ciphertextChars - parsed.ciphertextChars}",
            header.ciphertextChars - parsed.ciphertextChars <= 2
        )
    }
}
