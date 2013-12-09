package ssl

import java.net.Socket
import util._
import crypto._
import util.Util._
import ssl.SSLRecord._

abstract class SSLConnection(sock: Socket) {
	// IO
	val os = if (sock == null) null else sock.getOutputStream
	val is = if (sock == null) null else sock.getInputStream

	// sequence number
	var clientSeq = 0
	var serverSeq = 0

	// client/server random
	var clientRandom: Array[Byte] = null
	var serverRandom: Array[Byte] = null

	// record handshake messages
	var finishRecording = false
	var recordedHandshakes = Array[Byte]()

	// symmetric keys
	var clientMACKey = Array[Byte]()
	var serverMACKey = Array[Byte]()
	var clientWriteKey = Array[Byte]()
	var clientWriteRC4: RC4 = null
	var serverWriteKey = Array[Byte]()
	var serverWriteRC4: RC4 = null

	var masterSecret: Array[Byte] = null

	// flags
	var needDecrypt = false

	val sbArray = new StreamBasedArray(is)
	def recv(len: Int): Array[Byte] = {
		sbArray.nextBytes(len)
	}

	def recvRecord(contentType: Int): Array[Byte] = {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, contentType)
		recv(len)
	}

	def send(msg: Array[Byte]) {
		os.write(msg)
	}

	def close {
		sock.close
	}

	/*
	 * NOTE:
	 * 1. only record handshake message before the current Finish handshake message
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

	def dump4keys {
		printf("Client MAC Key: "); dumpByteArray(clientMACKey)
		printf("Server MAC Key: "); dumpByteArray(serverMACKey)
		printf("Client Write Key: "); dumpByteArray(clientWriteKey)
		printf("Server Write Key: "); dumpByteArray(serverWriteKey)
	}

	def recvChangeCipherSpec = {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, CT_CHANGE_CIPHER_SPEC)
		val data = recv(len)
		assert(len == 1)
		assert(data(0) == 1.asInstanceOf[Byte])
		this.needDecrypt = true
	}

	def decryptData(origData: Array[Byte]): Array[Byte]

	// hmacEntity indicates we should generate which sides hmac
	def decryptVerifyData(hmacEntity: Int, contentType: Int, origData: Array[Byte]): Array[Byte] = {
		var data = decryptData(origData)
		assert(data.length > 16)
		
		val actHmac = data.slice(data.length - 16, data.length)
		data = data.slice(0, data.length - 16)

		val hmacAgt = new RecordHMAC(this)
		val expHmac = hmacAgt.genHMAC(hmacEntity, contentType, data)

		assert(byteArrayEq(actHmac, expHmac))
		data
	}

	/*
	 * entityType indicate the data is from server or client
	 */
	def recvAppData(entityType: Int): Array[Byte] = {
		val header = recv(5)
		val len = SSLRecord.validateHeader(header, CT_APPLICATION_DATA)
		var data = recv(len)

		data = decryptVerifyData(entityType, CT_APPLICATION_DATA, data)
		data
	}

	def sendChangeCipherSpec {
		// sample 14 03 00 00 01 01 
		val record = SSLRecord.createChangeCipherSpec(Array[Byte](1))
		send(record.serialize)
	}
}
