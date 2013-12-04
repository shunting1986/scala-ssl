package ssl

import util._
import crypto._

class ClientKeyExchange(conn: SSLConnection) {
	// generate PreMasterSecret
	val pms = Array[Byte](3, 0) ++ Util.genRandom(46)  // tricky how I find this...

	val prfAgt = new PRF
	val ms = {
		val output = new Array[Byte](48)
		assert(conn.clientRandom != null)
		assert(conn.serverRandom != null)
		prfAgt.prf(pms, conn.clientRandom, conn.serverRandom, output)
		conn.masterSecret = output
		output
	}
	val keyblock = {
		val output = new Array[Byte](64)
		prfAgt.prf(ms, conn.serverRandom, conn.clientRandom, output)
		output
	}

	val dummy = {
		conn.clientMACKey = keyblock.slice(0, 16)
		conn.serverMACKey = keyblock.slice(16, 32)
		conn.clientWriteKey = keyblock.slice(32, 48)
		conn.clientWriteRC4 = new RC4(conn.clientWriteKey)
		conn.serverWriteKey = keyblock.slice(48, 64)
		conn.serverWriteRC4 = new RC4(conn.serverWriteKey)
	}

	def serialize: Array[Byte] = {
		// using server's public key to encode the PreMasterSecret
		assert(conn.publicKey != null)

		val rsa = new RSA
		val epms = rsa.encrypt(pms, conn.publicKey) 

		// send the encrypted PreMasterSecret
		Handshake.genClientKeyExchange(epms)
	}
}
