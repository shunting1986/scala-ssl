package ssl

import java.net.Socket
import util.StreamBasedArray
import util.Util._

/* This class manage all the low level socket read/write */
class SSLConnection(host: String, port: Int) {
	val sock = new Socket(host, port)
	val os = sock.getOutputStream
	val is = sock.getInputStream
	val sbArray = new StreamBasedArray(is)

	def send(msg: Array[Byte]) {
		os.write(msg)
	}

	def recv(len: Int): Array[Byte] = {
		sbArray.nextBytes(len)
	}

	def sendClientHello() {
		val ch = new ClientHello
		val msg = ch.toHandshake(ch.genClientHello)
		send(msg)
	}

	def recvServerHello(): ServerHello = {
		val sh = new ServerHello
		sh.recvServerHello(this)
		sh
	}
}
