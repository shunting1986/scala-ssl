package ssl

import util.Util._
import util.ArrayBasedReader
import der.DerDecoder

class Handshake {
	def HANDSHAKE: Byte = 0x16

	def CLIENT_HELLO: Byte = 0x01
	def SERVER_HELLO: Byte = 0x02
	def CERTIFICATE_HS: Byte = 11

	def MAJVER: Byte = 0x03
	def MINVER: Byte = 0x00

	def toHandshake(msg: Array[Byte]) : Array[Byte] = {
		Array[Byte](HANDSHAKE, MAJVER, MINVER) ++ intToByteArray(msg.length, 2) ++ msg
	}

	def decodeServerHello(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val maj = reader.nextInt(1)
		val min = reader.nextInt(1)
		assert(maj == MAJVER)
		assert(min == MINVER)

		val serverRandom = reader.nextBytes(32)
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

		assert(!reader.hasMore)
	}

	def decodeCertificateHS(data: Array[Byte]) {
		val reader = new ArrayBasedReader(data)
		val totLen = reader.nextInt(3)

		assert(totLen == reader.leftLength)

		while (reader.hasMore) {
			val certLen = reader.nextInt(3)
			val certData = reader.nextBytes(certLen)

			printf("Cert:\n")
			// dumpByteArray(certData)

			val derDecoder = new DerDecoder
			derDecoder.decode(certData)
		}
	}

	def decodeHandshake(typ: Int, data: Array[Byte]) {
		if (typ == SERVER_HELLO) {
			decodeServerHello(data)
		} else if (typ == CERTIFICATE_HS) {
			decodeCertificateHS(data)
		} else {
			printf("Type = %d\n", typ)
			sys.error("Unsupported type")
		}
	}
}
