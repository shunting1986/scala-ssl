package crypto

import util.Util._
import cert._

object RSA {
	def main(args: Array[String]) {
		// Do encryption first
		val cert = new X509Certificate
		cert.parsePemFile("/tmp/server.crt")
		// TODO

		/*
		// steam to byte array
		val input = streamToByteArray(System.in)

		// byte array to big number
		val bi = byteArrayToBigInt(input)

		// load private key
		val privateKey = new PrivateKey
		privateKey.parsePemFile("/tmp/server.key")

		val rsa = new RSA
		val res = rsa.transformToByteArray(bi, privateKey.privateExponent, privateKey.modulus)

		dumpByteArray(res)
		 */
	}
}

class RSA {
	def transformToByteArray(base: BigInt, exponent: BigInt, modulus: BigInt): Array[Byte] = {
		val resBi = transform(base, exponent, modulus)
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
