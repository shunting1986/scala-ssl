package ssl

import util.Util._
import util.ArrayBasedReader
import der.DerNode
import cert._
import ssl.SSLConstants._

object Handshake {
	def CLIENT_HELLO = 0x01
	def SERVER_HELLO: Byte = 0x02
	def CERTIFICATE: Byte = 11
	def SERVER_HELLO_DONE: Byte = 14
	def CLIENT_KEY_EXCHANGE = 0x10
	def FINISHED = 0x14

	def genClientHelloHandshake(payload: Array[Byte]): Array[Byte] = {
		genHandshake(CLIENT_HELLO, payload)
	}

	def genClientKeyExchange(payload: Array[Byte]): Array[Byte] = {
		genHandshake(CLIENT_KEY_EXCHANGE, payload)
	}

	def genFinished(payload: Array[Byte]): Array[Byte] = {
		genHandshake(FINISHED, payload)
	}

	def genHandshake(hkType: Int, payload: Array[Byte]): Array[Byte] = {
		Array[Byte](hkType.asInstanceOf[Byte]) ++ intToByteArray(payload.length, 3) ++ payload
	}
}

class Handshake(conn: SSLClientConnection) {
	def decodeServerHelloDone(data: Array[Byte]) {
		assert(data.length == 0)
		printf("Get Server Hello Done\n")
	}

	def decodeHandshake(typ: Int, data: Array[Byte]) {
		if (typ == Handshake.SERVER_HELLO) {
			(new ServerHello(conn)).decode(data)
		} else if (typ == Handshake.CERTIFICATE) {
			conn.serverCertReceived = true
			(new CertificateHS(conn)).decode(data)
		} else if (typ == Handshake.SERVER_HELLO_DONE) {
			conn.serverHelloDoneReceived = true
			decodeServerHelloDone(data)
		} else if (typ == Handshake.FINISHED) { 
			val finishAgt = new FinishedHS(conn, SERVER_TO_CLIENT) 
			finishAgt.verifyServerFinishMsg(data)
			printf("Pass validation for server finished message\n")
		} else {
			printf("Type = %d\n", typ)
			sys.error("Unsupported type")
		}
	}
}
