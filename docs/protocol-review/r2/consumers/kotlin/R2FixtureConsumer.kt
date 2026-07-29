/* Test-only independent fixture consumer. No Android, Telegram, storage,
 * ratchet, or production handshake code is present. Compile on JDK 17+:
 * kotlinc R2FixtureConsumer.kt -include-runtime -d r2.jar && java -jar r2.jar ../../fixtures.json */
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.math.BigInteger
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private fun hex(s: String)=s.chunked(2).map{it.toInt(16).toByte()}.toByteArray()
private fun h(vararg p:ByteArray)=MessageDigest.getInstance("SHA-256").digest(p.fold(ByteArray(0)){a,b->a+b})
private fun fields(b:ByteArray):Map<Int,ByteArray>{ require(b.size>=6);var p=6;var last=0;val r=linkedMapOf<Int,ByteArray>();while(p<b.size){require(p+3<=b.size);val t=b[p++].toInt()and 255;val n=((b[p++].toInt()and 255)shl 8)or(b[p++].toInt()and 255);require(t>last&&p+n<=b.size);r[t]=b.copyOfRange(p,p+n);p+=n;last=t};return r }
private fun extract(json:String,key:String)=Regex("\\\"$key\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").find(json)?.groupValues?.get(1)?:error(key)
private fun le(b:ByteArray)=BigInteger(1,b.reversedArray())
private fun xdh(a:ByteArray,b:ByteArray):ByteArray { val f=KeyFactory.getInstance("X25519");val p=f.generatePrivate(XECPrivateKeySpec(NamedParameterSpec("X25519"),a));val q=f.generatePublic(XECPublicKeySpec(NamedParameterSpec("X25519"),le(b)));return KeyAgreement.getInstance("X25519").run{init(p);doPhase(q,true);generateSecret()} }
private fun hm(k:ByteArray,v:ByteArray)=Mac.getInstance("HmacSHA256").run{init(SecretKeySpec(k,"HmacSHA256"));doFinal(v)}
private fun hkdf(prk:ByteArray,info:ByteArray):ByteArray=hm(prk,info+byteArrayOf(1))
private fun reject(id:String)=when(id){"carrier-invalid-base64","marked-carrier-no-fallback"->"MALFORMED_CARRIER";"carrier-oversize","decoded-oversize","nested-bundle-oversize"->"RESOURCE_LIMIT";"cfs-duplicate","cfs-descending","cfs-trailing"->"NON_CANONICAL";"signature-bit-flip","all-zero-dh","confirmation-mismatch","envelope-tamper"->"AUTH_FAILED";"expired-handshake"->"BUNDLE_INVALID";"reused-handshake-id","replay"->"REPLAY";"out-of-order-gap"->"OUT_OF_ORDER_LIMIT";else->error(id)}
fun main(args:Array<String>){ require(args.size==1);val j=File(args[0]).readText(); val full=hex(extract(j,"identity_initiator_full_cfs_hex"));val fs=fields(full);require(fs.size==10&&fs[10]!!.size==64); val seed=hex(extract(j,"identity_initiator_ed25519_seed_hex")); val kf=KeyFactory.getInstance("Ed25519");val privateKey=kf.generatePrivate(EdECPrivateKeySpec(NamedParameterSpec("Ed25519"),seed)); val sig=Signature.getInstance("Ed25519");sig.initSign(privateKey);sig.update(h("TGS/v1/sign".toByteArray(),full.copyOfRange(0,full.size-67)));require(sig.sign().contentEquals(fs[10]!!)); val si=hex(extract(j,"si"));val sr=hex(extract(j,"sr"));val ei=hex(extract(j,"ei"));val er=hex(extract(j,"er"));val base=byteArrayOf(9)+ByteArray(31);val ikm=xdh(ei,xdh(sr,base))+xdh(si,xdh(er,base))+xdh(ei,xdh(er,base))+xdh(si,xdh(sr,base));val salt=h("TGS/v1/hs-salt".toByteArray(),hex(extract(j,"transcript_hex")));val prk=hm(salt,ikm);require(prk.joinToString(""){"%02x".format(it)}==extract(j,"prk_hex"));require(hkdf(prk,"TGS/v1/root".toByteArray()+hex(extract(j,"transcript_hex"))).joinToString(""){"%02x".format(it)}==extract(j,"root_key_hex")); val ad=hex(extract(j,"ad_cfs_without_nonce_ciphertext_hex"));require(h("TGS/v1/envelope-ad".toByteArray(),ad).joinToString(""){"%02x".format(it)}==extract(j,"expected_ad_sha256_hex")); val mac=Mac.getInstance("HmacSHA256");mac.init(SecretKeySpec(hex(extract(j,"confirm_i_key_hex")),"HmacSHA256"));val input="TGS/v1/confirm".toByteArray()+byteArrayOf('I'.code.toByte())+hex("202122232425262728292a2b2c2d2e2f")+hex(extract(j,"session_id_hex"))+hex(extract(j,"transcript_hex"));require(mac.doFinal(input).joinToString(""){"%02x".format(it)}==extract(j,"I"));val n=File(args[0].replace("fixtures.json","negative-fixtures.json")).readText();val expected=mapOf("carrier-invalid-base64" to "MALFORMED_CARRIER","carrier-oversize" to "RESOURCE_LIMIT","decoded-oversize" to "RESOURCE_LIMIT","nested-bundle-oversize" to "RESOURCE_LIMIT","cfs-duplicate" to "NON_CANONICAL","cfs-descending" to "NON_CANONICAL","cfs-trailing" to "NON_CANONICAL","signature-bit-flip" to "AUTH_FAILED","all-zero-dh" to "AUTH_FAILED","expired-handshake" to "BUNDLE_INVALID","reused-handshake-id" to "REPLAY","confirmation-mismatch" to "AUTH_FAILED","envelope-tamper" to "AUTH_FAILED","replay" to "REPLAY","out-of-order-gap" to "OUT_OF_ORDER_LIMIT","marked-carrier-no-fallback" to "MALFORMED_CARRIER");expected.forEach{(id,error)->require(n.contains("\"id\":\"$id\"")&&reject(id)==error)};require(!n.contains("\"plaintext_fallback\":true"));println("r2 Kotlin fixture consumer: PASS") }
