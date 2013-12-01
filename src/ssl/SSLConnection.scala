package ssl

import java.net.Socket
import util.StreamBasedArray
import util.Util._
import util.Util
import crypto._
import cert._

/* This class manage all the low level socket read/write */
class SSLConnection(host: String, port: Int) {
	val sock = if (host == null) null else new Socket(host, port)
	val os = if (sock == null) null else sock.getOutputStream
	val is = if (sock == null) null else sock.getInputStream
	val sbArray = new StreamBasedArray(is)

	var serverCert: X509Certificate = null
	def publicKey: PublicKey = serverCert.publicKey

	var sendSeq = 0
	var recvSeq = 0

	def send(msg: Array[Byte]) {
		os.write(msg)
	}

	def recv(len: Int): Array[Byte] = {
		sbArray.nextBytes(len)
	}

	def sendClientHello() {
		val ch = new ClientHello(this)
		val msg = ch.toHandshake(ch.genClientHello)
		send(msg)
	}

	def recvServerHello(): ServerHello = {
		val sh = new ServerHello(this)
		sh.recvServerHello(this)
		sh
	}

	/*
	 * Client send the 'ClientKeyExchange' handshake to server
	 */
	def sendClientKeyExchange() = {
		// generate PreMasterSecret
		val pms = Util.genRandom(48)

		// using server's public key to encode the PreMasterSecret
		assert(publicKey != null)

		val rsa = new RSA
		val epms = rsa.encrypt(pms, publicKey)

		// send the encrypted PreMasterSecret
		def toClientKeyExchange(msg: Array[Byte]): Array[Byte] = {
			Array[Byte](0x10) ++ Util.intToByteArray(msg.length, 3) ++ msg
		}

		val hkAgt = new Handshake(this)
		val hkMsg = hkAgt.toHandshake(toClientKeyExchange(epms))
		send(hkMsg)
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
