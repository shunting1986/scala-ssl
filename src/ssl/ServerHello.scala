package ssl

import util.Util._
import ssl.SSLConstants._
import util._

class ServerHello(conn: SSLConnection) {
	/////////////////////////
	// Server Hello Recv Part
	/////////////////////////
	def decode(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val maj = reader.nextInt(1)
		val min = reader.nextInt(1)
		assert(maj == MAJVER)
		assert(min == MINVER)

		val serverRandom = reader.nextBytes(32)
		conn.serverRandom = serverRandom
		println("Server Random:")
		dumpByteArray(serverRandom)

		val sessionIDLen = reader.nextInt(1)
		val sessionID = reader.nextBytes(sessionIDLen)
		println("Session ID:")
		dumpByteArray(sessionID)

		val cipherSuite = reader.nextInt(2)
		printf("CipherSuite %d\n", cipherSuite)

		val compressMethod = reader.nextInt(1)
		printf("CompressMethod %d\n", compressMethod)

		// assert(!reader.hasMore)
		if (reader.hasMore) {
			printf("+++++++ Server Hello has more information: \n")
			dumpByteArray(reader.getData)
		}
	}

	/////////////////////////
	// Server Hello Send Part
	/////////////////////////
	val serverRandom: Array[Byte] = {
		val random = genRandom(32)
		conn.serverRandom = random
		random
	}

	val serverSessionPart: Array[Byte] = {
		val random = genRandom(32)
		Array[Byte](32.asInstanceOf[Byte]) ++ random
	}

	val cipherSuite: Array[Byte] = {
		intToByteArray(SSL_RSA_WITH_RC4_128_MD5, 2)
	}

	val compressionMethod: Array[Byte] = {
		intToByteArray(0, 1)
	}

	def serialize: Array[Byte] = {
		val payload = Array[Byte](MAJVER, MINVER) ++ serverRandom ++ serverSessionPart ++ cipherSuite ++ compressionMethod
		Handshake.genServerHelloHandshake(payload)
	}
}
