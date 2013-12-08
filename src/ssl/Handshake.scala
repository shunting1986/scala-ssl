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

	def parseClientHello(payload: Array[Byte]): Array[Byte] = {
		parseHandshake(CLIENT_HELLO, payload)
	}

	def genServerHelloHandshake(payload: Array[Byte]): Array[Byte] = {
		genHandshake(SERVER_HELLO, payload)
	}

	def genCertificate(payload: Array[Byte]): Array[Byte] = {
		genHandshake(CERTIFICATE, payload)
	}

	def genServerHelloDone(payload: Array[Byte]): Array[Byte] = {
		genHandshake(SERVER_HELLO_DONE, payload)
	}

	def genClientKeyExchange(payload: Array[Byte]): Array[Byte] = {
		genHandshake(CLIENT_KEY_EXCHANGE, payload)
	}

	def parseClientKeyExchange(payload: Array[Byte]): Array[Byte] = {
		parseHandshake(CLIENT_KEY_EXCHANGE, payload)
	}

	def genFinished(payload: Array[Byte]): Array[Byte] = {
		genHandshake(FINISHED, payload)
	}

	def genHandshake(hkType: Int, payload: Array[Byte]): Array[Byte] = {
		Array[Byte](hkType.asInstanceOf[Byte]) ++ intToByteArray(payload.length, 3) ++ payload
	}

	// this method assumes the payload only contains one handshake message
	def parseHandshake(hkType: Int, payload: Array[Byte]): Array[Byte] = {
		val hkTypeBt = hkType.asInstanceOf[Byte]
		assert(hkTypeBt == payload(0))
		val len = byteArrayToInt(payload.slice(1, 4))
		val subdata = payload.slice(4, payload.length)
		assert(len == subdata.length)
		subdata
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
