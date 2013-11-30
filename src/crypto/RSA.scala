package crypto

import util._
import util.Util._
import cert._

object RSA {
	def main(args: Array[String]) {
		// Do encryption first
		val cert = new X509Certificate
		cert.parsePemFile("/tmp/server.crt")

		// plain text
		val plainText = streamToByteArray(System.in)
		printf("Origin Plain Text:\n")
		dumpByteArray(plainText)

		// do encryption
		val rsa = new RSA
		val genCipherText = rsa.encrypt(plainText, cert.publicKey)

		val privateKey = new PrivateKey
		privateKey.parsePemFile("/tmp/server.key")

		val genPlainText = rsa.decrypt(genCipherText, privateKey)
		printf("generated plain text:\n")
		dumpByteArray(genPlainText)
	}
}

class RSA {
	def decrypt(cipherText: Array[Byte], privateKey: PrivateKey): Array[Byte] = {
		val cipherBi = byteArrayToBigInt(cipherText)
		val privateExponent = privateKey.privateExponent
		val modulus = privateKey.modulus

		assert(cipherBi < modulus)
		val resBi = transform(cipherBi, privateExponent, modulus)
		removePadding(resBi, modulus)
	}

	def encrypt(plainText: Array[Byte], publicKey: PublicKey): Array[Byte] = {
		val publicExponent = publicKey.publicExponent
		val modulus = publicKey.modulus

		val paddedPlainText = addPadding(plainText, publicKey.modulus)
		val base = Util.byteArrayToBigInt(paddedPlainText)
		val resBi = transform(base, publicExponent, modulus)
		Util.bigIntToByteArray(resBi, (modulus.bitLength + 7) / 8)
	}

	def addPadding(plainText: Array[Byte], modulus: BigInt): Array[Byte] = {
		// EB = 00 || BT || PS || 00 || D
		val totLen = (modulus.bitLength + 7) / 8
		assert(plainText.length + 3 <= totLen)

		val blockType: Byte = 2

		def genPadding(len: Int): Array[Byte] = {
			if (len == 0) {
				Array[Byte]()
			} else {
				def genOnePadding: Byte = {
					val randAr = Util.genRandom(1)
					if (randAr(0) == 0) {
						genOnePadding
					} else {
						randAr(0)
					}
				}
				genPadding(len - 1) :+ genOnePadding
			}
		}

		var paddingStr = genPadding(totLen - 3 - plainText.length)
		Array[Byte](0) ++ Array[Byte](blockType) ++ paddingStr ++ Array[Byte](0) ++ plainText
	}

	def removePadding(resBi: BigInt, modulus: BigInt): Array[Byte] = {
		val mbitlen = modulus.bitLength
		val mbytelen = (mbitlen + 7) / 8 
		val resAr = bigIntToByteArray(resBi, mbytelen)
		assert(resAr(0) == 0)
		assert(resAr(1) == 2)

		var i = 2
		while (i < resAr.length && resAr(i) != 0) {
			i += 1
		}
		assert(i < resAr.length)
		resAr.slice(i + 1, resAr.length)
	}

	def transform(base: BigInt, exponent: BigInt, modulus: BigInt): BigInt = {
		if (exponent == 0) {
			1
		} else {
			val half = transform(base, exponent / 2, modulus)
			if (exponent % 2 == 0) {
				(half * half) % modulus
			} else {
				(half * half * base) % modulus
			}
		}
	}
}
