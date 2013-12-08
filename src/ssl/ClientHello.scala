package ssl

import util.Util._
import util._
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

	////////////////////////
	// client header recving 
	////////////////////////
	def validateVersion(reader: ArrayBasedReader) {
		val maj = reader.nextInt(1)
		val min = reader.nextInt(1)
		assert(maj == MAJVER)
		assert(min == MINVER)
	}

	def parseClientSession(reader: ArrayBasedReader) {
		val len = reader.nextInt(1)
		if (len != 0) {
			val id = reader.nextBytes(len)
			printf("Client Session ID:\n")
			dumpByteArray(id)
		}
	}

	def parseCipherSuites(reader: ArrayBasedReader) {
		val len = reader.nextInt(2)
		assert(len % 2 == 0)
		var i = 0
		var found = false
		while (i < len) {
			val cs = reader.nextInt(2)
			if (cs == SSL_RSA_WITH_RC4_128_MD5) 
				found = true
			i += 2
		}
		if (!found) {
			sys.error("Client does not support SSL_RSA_WITH_RC4_128_MD5")
		}
	}

	def parseCompressionMethods(reader: ArrayBasedReader) {
		val len = reader.nextInt(1)
		printf("Client Support following compression methods:\n")
		var i = 0
		while (i < len) {
			val cm = reader.nextInt(1)
			printf(" %d\n", cm)
			i += 1
		}
	}

	def parse(_data: Array[Byte]) {
		val data = Handshake.parseClientHello(_data)

		val reader = new ArrayBasedReader(data)
		validateVersion(reader)
		conn.clientRandom = reader.nextBytes(32)
		parseClientSession(reader)
		parseCipherSuites(reader)
		parseCompressionMethods(reader)

		assert(!reader.hasMore)
	}
}
