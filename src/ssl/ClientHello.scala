package ssl

import util.Util._
import ssl.SSLConstants._

class ClientHello(conn: SSLConnection) {
	def cipherSuiteList: Array[Byte] = {
		var cs = intToByteArray(SSL_RSA_WITH_RC4_128_MD5, 2) 
		// cs = cs ++ intToByteArray(0xff, 2) // Is this important?? This will make some difference!
		intToByteArray(cs.length, 2) ++ cs
	}
	
	def compressMethodList: Array[Byte] = {
		var cm = Array[Byte]()
		// cm = cm ++ intToByteArray(1, 1) // Is this important?
		cm = cm ++ intToByteArray(NULL_COMPRESS, 1)
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
		val hkData = Handshake.genClientHelloHandshake(payload)
		conn.recordHandshake(hkData)
		SSLRecord.createHandshake(hkData).serialize
	}
}
