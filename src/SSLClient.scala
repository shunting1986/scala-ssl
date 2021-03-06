import ssl._
import util.Util._
import util.StreamBasedArray
import java.net.Socket

object SSLClient {
	def main(args: Array[String]) {
		assert(args.length == 2)
		val host = args(0)
		val port = Integer.parseInt(args(1))

		val sock = new Socket(host, port)
		val conn = new SSLClientConnection(sock)

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
		val data = conn.recvAppData
		printf(new String(data))
		printf("============= END   DATA ===============\n")

		conn.recvServerAlert
		conn.sendClientAlert
	
		conn.close
		// spin
	}
}

