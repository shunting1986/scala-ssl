package ssl

import util._
import util.Util._
import crypto._

class ClientKeyExchange(conn: SSLConnection) {
	//////////////
	// Common Part
	//////////////
	
	var pms = Array[Byte]()

	val prfAgt = new PRF
	def genms(_pms: Array[Byte]) = {
		val output = new Array[Byte](48)
		assert(conn.clientRandom != null)
		assert(conn.serverRandom != null)
		prfAgt.prf(_pms, conn.clientRandom, conn.serverRandom, output)
		conn.masterSecret = output
		output
	}
	def genkeyblock(_ms: Array[Byte]) = {
		val output = new Array[Byte](64)
		prfAgt.prf(_ms, conn.serverRandom, conn.clientRandom, output)
		output
	}

	def gen4keys(kb: Array[Byte]) = {
		conn.clientMACKey = kb.slice(0, 16)
		conn.serverMACKey = kb.slice(16, 32)
		conn.clientWriteKey = kb.slice(32, 48)
		conn.clientWriteRC4 = new RC4(conn.clientWriteKey)
		conn.serverWriteKey = kb.slice(48, 64)
		conn.serverWriteRC4 = new RC4(conn.serverWriteKey)
	}

  //////////////
	// Client Part
	//////////////
	def cliconn = conn.asInstanceOf[SSLClientConnection]

	def serialize: Array[Byte] = {
		// using server's public key to encode the PreMasterSecret
		assert(cliconn.publicKey != null)

		pms = Array[Byte](3, 0) ++ Util.genRandom(46)  // tricky how I find this...
		gen4keys(genkeyblock(genms(pms)))

		val rsa = new RSA
		val epms = rsa.encrypt(pms, cliconn.publicKey) 

		// send the encrypted PreMasterSecret
		Handshake.genClientKeyExchange(epms)
	}

  //////////////
  // Server Part
  ////////////// 
	def serconn = conn.asInstanceOf[SSLServerConnection]

	def parse(_data: Array[Byte]) {
		val encPMS = Handshake.parseClientKeyExchange(_data)

		val rsa = new RSA
		val pms = rsa.decrypt(encPMS, serconn.privateKey)
		gen4keys(genkeyblock(genms(pms)))
	}
}
