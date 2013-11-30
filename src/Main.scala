import ssl._
import util.Util._
import util.StreamBasedArray

object Main {
	def main(args: Array[String]) {
		val host = "127.0.0.1"
		val port = 8443
		val conn = new SSLConnection(host, port)

		conn.sendClientHello

		val sh = conn.recvServerHello
		conn.sendClientKeyExchange

		conn.sendClientChangeCipherSpec
		spin
	}
}

