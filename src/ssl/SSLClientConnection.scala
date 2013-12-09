package ssl

import java.net.Socket
import util.StreamBasedArray
import util.Util._
import util.Util
import crypto._
import cert._
import ssl.SSLConstants._
import ssl.SSLRecord._

/* This class manage all the low level socket read/write */
class SSLClientConnection(sock: Socket) extends SSLConnection(sock) {
	// PKI
	var serverCert: X509Certificate = null
	def publicKey: PublicKey = serverCert.publicKey

	// flags
	var serverCertReceived = false
	var serverHelloDoneReceived = false

	def decryptVerifyServerData(contentType: Int, origData: Array[Byte]): Array[Byte] = {
		decryptVerifyData(SERVER, contentType, origData)
	}

	override def decryptData(origData: Array[Byte]): Array[Byte] = {
		serverWriteRC4.decrypt(origData)
	}

	// client need this
	def sendClientHello() {
		send((new ClientHello(this)).serialize)
	}

	def recvServerHandshake() = {
		(new ServerHandshake(this)).recvServerHandshake
	}

	def recvServerChangeCipherSpec = {
		recvChangeCipherSpec
		printf("GET Server change cipher spec\n")
	}

	/*
	 * Client send the 'ClientKeyExchange' handshake to server
	 */
	def sendClientKeyExchange() = {
		val hkData = (new ClientKeyExchange(this)).serialize
		recordHandshake(hkData)
		send(SSLRecord.createHandshake(hkData).serialize)

		dump4keys
	}

	def sendClientChangeCipherSpec {
		sendChangeCipherSpec
	}

	def sendClientFinishedHandshake {
		val hkData = (new FinishedHS(this, CLIENT_TO_SERVER)).serialize
		send(SSLRecord.createHandshake(hkData).serialize)
		finishRecording = true
	}

	override def sendRecord(contentType: Int, plainText: Array[Byte]) {
		sendRecord(CLIENT_TO_SERVER, contentType, plainText)
	}

	def sendAppData(plainText: Array[Byte]) {
		sendRecord(SSLRecord.CT_APPLICATION_DATA, plainText)
	}

	def sendClientAlert {
		sendAlert
	}

	def recvAppData: Array[Byte] = {
		recvAppData(SERVER)
	}

	def recvServerAlert {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, CT_ALERT)
		var data = recv(len)

		data = decryptVerifyServerData(CT_ALERT, data)
		assert(data.length == 2)

		val alertObj = new Alert(data(0), data(1))
		println(alertObj)
	}
}
