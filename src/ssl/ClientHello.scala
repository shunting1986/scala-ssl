package ssl

import util.Util._
import ssl.SSLConstants._

class ClientHello(conn: SSLConnection) {
	def cipherSuiteList: Array[Byte] = {
		val cs = intToByteArray(SSL_RSA_WITH_RC4_128_MD5, 2)
		intToByteArray(cs.length, 2) ++ cs
	}
	
	def compressMethodList: Array[Byte] = {
		val cm = intToByteArray(NULL_COMPRESS, 1)
		intToByteArray(cm.length, 1) ++ cm
	}

	val clientRandom: Array[Byte] = {
		val random = genRandom(32)
		conn.clientRandom = random
		random
	}

	val payload: Array[Byte] = {
		Array[Byte](MAJVER, MINVER) ++ clientRandom ++ Array[Byte](0) ++ cipherSuiteList ++ compressMethodList
	}

	def serialize(): Array[Byte] = {
		SSLRecord.createHandshake(Handshake.genClientHelloHandshake(payload)).serialize
	}
}
