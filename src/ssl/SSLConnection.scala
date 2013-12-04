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
class SSLConnection(host: String, port: Int) {
	// IO
	val sock = if (host == null) null else new Socket(host, port)
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
	var sendSeq = 0
	var recvSeq = 0

	// client/server random
	var clientRandom: Array[Byte] = null
	var serverRandom: Array[Byte] = null

	// flags
	// var doRecording = true
	var recordedHandshakes = Array[Byte]()

	var serverCertReceived = false
	var serverHelloDoneReceived = false

	/*
	 * NOTE:
	 * 1. only record handshake message before the client Finish handshake message
	 * 2. the content type header is not counted
	 */
	def recordHandshake(hkData: Array[Byte]) {
		recordedHandshakes = recordedHandshakes ++ hkData
	}

	def send(msg: Array[Byte]) {
		os.write(msg)
		/*
		if (doRecording) {
			recordedHandshakes = recordedHandshakes ++ msg
		}
		 */
	}

	val sbArray = new StreamBasedArray(is)
	def recv(len: Int): Array[Byte] = {
		val res = sbArray.nextBytes(len)
		/*
		if (doRecording) {
			recordedHandshakes = recordedHandshakes ++ res
		}
		 */
		res
	}

	def sendClientHello() {
		send((new ClientHello(this)).serialize)
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
		send(SSLRecord.createHandshake((new FinishedHS(this, CLIENT_TO_SERVER)).serialize).serialize)
	}
}
