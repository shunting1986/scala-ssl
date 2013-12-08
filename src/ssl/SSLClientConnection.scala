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
class SSLClientConnection(sock: Socket) {
	// IO
	val os = if (sock == null) null else sock.getOutputStream
	val is = if (sock == null) null else sock.getInputStream

	// PKI
	var serverCert: X509Certificate = null
	def publicKey: PublicKey = serverCert.publicKey

	// symmetric keys
	var clientMACKey = Array[Byte]()
	var serverMACKey = Array[Byte]()
	var clientWriteKey = Array[Byte]()
	var clientWriteRC4: RC4 = null
	var serverWriteKey = Array[Byte]()
	var serverWriteRC4: RC4 = null

	var masterSecret: Array[Byte] = null

	// sequence number
	var clientSeq = 0
	var serverSeq = 0

	// client/server random
	var clientRandom: Array[Byte] = null
	var serverRandom: Array[Byte] = null

	// record handshake messages
	var finishRecording = false
	var recordedHandshakes = Array[Byte]()

	// flags
	var serverCertReceived = false
	var serverHelloDoneReceived = false
	var needDecrypt = false

	def close {
		sock.close
	}

	/*
	 * NOTE:
	 * 1. only record handshake message before the client Finish handshake message
	 * 2. the content type header is not counted
	 */
	def recordHandshake(hkData: Array[Byte]) {
		recordedHandshakes = recordedHandshakes ++ hkData
	}

	def recordHandshakeCond(hkData: Array[Byte]) {
		if (!finishRecording) {
			recordHandshake(hkData)
		}
	}

	def send(msg: Array[Byte]) {
		os.write(msg)
	}

	val sbArray = new StreamBasedArray(is)
	def recv(len: Int): Array[Byte] = {
		sbArray.nextBytes(len)
	}

	def decryptVerifyServerData(contentType: Int, origData: Array[Byte]): Array[Byte] = {
		var data = this.decryptServerData(origData)
		assert(data.length > 16)
		
		val actHmac = data.slice(data.length - 16, data.length)
		data = data.slice(0, data.length - 16)

		val hmacAgt = new RecordHMAC(this)
		val expHmac = hmacAgt.genServerHMAC(contentType, data)

		assert(byteArrayEq(actHmac, expHmac))
		data
	}

	def decryptServerData(origData: Array[Byte]): Array[Byte] = {
		val decData = serverWriteRC4.decrypt(origData)
		decData
	}

	// client need this
	def sendClientHello() {
		send((new ClientHello(this)).serialize)
	}

	// server need this
	def recvClientHello() {
		// TODO
	}

	def recvServerHandshake() = {
		(new ServerHandshake(this)).recvServerHandshake
	}

	def recvServerChangeCipherSpec = {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, CT_CHANGE_CIPHER_SPEC)
		val data = recv(len)
		assert(len == 1)
		assert(data(0) == 1.asInstanceOf[Byte])
		printf("GET Server change cipher spec\n");
		this.needDecrypt = true
	}

	/*
	 * Client send the 'ClientKeyExchange' handshake to server
	 */
	def sendClientKeyExchange() = {
		val hkData = (new ClientKeyExchange(this)).serialize
		recordHandshake(hkData)
		send(SSLRecord.createHandshake(hkData).serialize)

		printf("Client MAC Key: "); dumpByteArray(clientMACKey)
		printf("Server MAC Key: "); dumpByteArray(serverMACKey)
		printf("Client Write Key: "); dumpByteArray(clientWriteKey)
		printf("Server Write Key: "); dumpByteArray(serverWriteKey)
	}

	def sendClientChangeCipherSpec {
		// sample 14 03 00 00 01 01 
		// doRecording = false // do not record the ChangeCipherSpec sent by client which is not a handshake
		val record = SSLRecord.createChangeCipherSpec(Array[Byte](1))
		send(record.serialize)
	}

	def sendClientFinishedHandshake {
		val hkData = (new FinishedHS(this, CLIENT_TO_SERVER)).serialize
		send(SSLRecord.createHandshake(hkData).serialize)
		finishRecording = true
	}

	def sendClientRecord(contentType: Int, plainText: Array[Byte]) {
		val rc4 = this.clientWriteRC4 
		val hmacAgt = new RecordHMAC(this)
		var hmac = hmacAgt.genClientHMAC(contentType.asInstanceOf[Byte], plainText)
		val cipherText = rc4.encrypt(plainText ++ hmac)
		send((new SSLRecord(contentType, cipherText)).serialize)
	}

	def sendAppData(plainText: Array[Byte]) {
		sendClientRecord(SSLRecord.CT_APPLICATION_DATA, plainText)
	}

	def sendClientAlert {
		val data = Array[Byte](Alert.LEVEL_WARNING.asInstanceOf[Byte], Alert.DESC_CLOSE_NOTIFY.asInstanceOf[Byte])
		sendClientRecord(SSLRecord.CT_ALERT, data)
	}

	def recvAppData {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, CT_APPLICATION_DATA)
		var data = recv(len)

		data = decryptVerifyServerData(CT_APPLICATION_DATA, data)
		printf(new String(data))
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
