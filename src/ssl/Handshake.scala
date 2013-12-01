package ssl

import util.Util._
import util.ArrayBasedReader
import der.DerNode
import cert._

object Handshake {
	def CLIENT_HELLO = 0x01
	def SERVER_HELLO: Byte = 0x02
	def CERTIFICATE: Byte = 11
	def SERVER_HELLO_DONE: Byte = 14

	def genClientHelloHandshake(payload: Array[Byte]): Array[Byte] = {
		genHandshake(CLIENT_HELLO, payload)
	}

	def genHandshake(hkType: Int, payload: Array[Byte]): Array[Byte] = {
		Array[Byte](hkType.asInstanceOf[Byte]) ++ intToByteArray(payload.length, 3) ++ payload
	}
}

class Handshake(conn: SSLConnection) {
	def decodeServerHelloDone(data: Array[Byte]) {
		assert(data.length == 0)
		printf("Get Server Hello Done\n")
	}

	def decodeHandshake(typ: Int, data: Array[Byte]) {
		if (typ == Handshake.SERVER_HELLO) {
			(new ServerHello(conn)).decode(data)
		} else if (typ == Handshake.CERTIFICATE) {
			(new CertificateHS(conn)).decode(data)
		} else if (typ == Handshake.SERVER_HELLO_DONE) {
			decodeServerHelloDone(data)
		} else {
			printf("Type = %d\n", typ)
			sys.error("Unsupported type")
		}
	}
}
