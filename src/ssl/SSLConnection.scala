package ssl

import java.net.Socket
import util.StreamBasedArray
import util.Util._
import util.Util
import crypto._
import cert._

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
	var serverWriteKey = Array[Byte]()

	// sequence number
	var sendSeq = 0
	var recvSeq = 0

	// client/server random
	var clientRandom: Array[Byte] = null
	var serverRandom: Array[Byte] = null

	def send(msg: Array[Byte]) {
		os.write(msg)
	}

	val sbArray = new StreamBasedArray(is)
	def recv(len: Int): Array[Byte] = {
		sbArray.nextBytes(len)
	}

	def sendClientHello() {
		send((new ClientHello(this)).serialize)
	}

	def recvServerHandshake() = {
		(new ServerHandshake(this)).recvServerHandshake
	}

	/*
	 * Client send the 'ClientKeyExchange' handshake to server
	 */
	def sendClientKeyExchange() = {
		send(SSLRecord.createHandshake((new ClientKeyExchange(this)).serialize).serialize)

		printf("Client MAC Key: "); dumpByteArray(clientMACKey)
		printf("Server MAC Key: "); dumpByteArray(serverMACKey)
		printf("Client Write Key: "); dumpByteArray(clientWriteKey)
		printf("Server Write Key: "); dumpByteArray(serverWriteKey)
	}

	def sendClientChangeCipherSpec {
		// sample 14 03 00 00 01 01 
		val record = SSLRecord.createChangeCipherSpec(Array[Byte](1))
		send(record.serialize)
	}

	def sendClientFinishedHandshake {
		sys.error("ni")
	}
}
