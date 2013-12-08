package ssl

import java.net.Socket
import ssl._
import util.Util._
import cert._
import ssl.SSLConstants._
import ssl.SSLRecord._

class SSLServerConnection(sock: Socket, certPath: String, keyPath: String) extends SSLConnection(sock) {
	val serverCertDer = {
		val certObj = new X509Certificate
		certObj.pemFileToDer(certPath)
	}

	val privateKey = {
		val pk = new PrivateKey
		pk.parsePemFile(keyPath)
		pk
	}

	def recvClientHello {
		val data = recvRecord(SSLRecord.CT_HANDSHAKE)
		recordHandshake(data)
		(new ClientHello(this)).parse(data)
	}

	def sendServerHello {
		val hkdata = (new ServerHello(this)).serialize
		recordHandshake(hkdata)
		send(SSLRecord.createHandshake(hkdata).serialize)
	}

	def sendServerCertificate {
		val hkdata = (new CertificateHS(this)).serialize
		recordHandshake(hkdata)
		send(SSLRecord.createHandshake(hkdata).serialize)
	}

	def sendServerHelloDone {
		val payload = Array[Byte]() // empty
		val hkData = Handshake.genServerHelloDone(payload)

		recordHandshake(hkData)
		send(SSLRecord.createHandshake(hkData).serialize)
	}

	def recvClientKeyExchange {
		val data = recvRecord(SSLRecord.CT_HANDSHAKE)
		recordHandshake(data)
		(new ClientKeyExchange(this)).parse(data)

		dump4keys
	}

	def recvClientChangeCipherSpec = {
		recvChangeCipherSpec
		printf("GET Client change cipher spec\n")
	}

	def decryptVerifyClientData(contentType: Int, origData: Array[Byte]): Array[Byte] = {
		decryptVerifyData(CLIENT, contentType, origData)
	}

	override def decryptData(data: Array[Byte]): Array[Byte] = {
		clientWriteRC4.decrypt(data)
	}

	def recvClientFinishedHandshake = {
		var data = recvRecord(SSLRecord.CT_HANDSHAKE)
		// decrypt
		data = decryptVerifyClientData(CT_HANDSHAKE, data)

		data = Handshake.parseFinished(data)
		val finishedAgt = new FinishedHS(this, CLIENT_TO_SERVER)
		finishedAgt.verifyClientFinishMsg(data)
		printf("Pass validation for client finished message\n")

		recordHandshake(data) // must put this later!!
		finishRecording = true
	}
}
