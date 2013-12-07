import ssl._
import util.Util._
import util.StreamBasedArray

object SSLClient {
	def main(args: Array[String]) {
		val host = "127.0.0.1"
		val port = 8443
		val conn = new SSLConnection(host, port)

		conn.sendClientHello
		conn.recvServerHandshake
		if (!conn.serverCertReceived) {
			conn.recvServerHandshake
		}
		if (!conn.serverHelloDoneReceived) {
			conn.recvServerHandshake
		}

		conn.sendClientKeyExchange
		conn.sendClientChangeCipherSpec
		conn.sendClientFinishedHandshake

		conn.recvServerChangeCipherSpec
		conn.recvServerHandshake // actually used to receive the server Finish record

		conn.sendAppData("GET /hi HTTP/1.0\n\n".getBytes)
		printf("============= BEGIN DATA ===============\n")
		conn.recvAppData
		printf("============= END   DATA ===============\n")

		conn.recvServerAlert
		conn.sendClientAlert
	
		conn.close
		// spin
	}
}

