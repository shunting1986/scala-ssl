import java.net.ServerSocket
import util.Util._

import ssl._

object SSLServer {
	def main(args: Array[String]) {
		assert(args.length == 2)
		val listenSock = new ServerSocket(8888)

		printf("Waiting for connect...\n")
		val workSock = listenSock.accept
		val certPath = args(0)
		val keyPath = args(1)
		val conn = new SSLServerConnection(workSock, certPath, keyPath)

		conn.recvClientHello // one handshake record
		conn.sendServerHello
		conn.sendServerCertificate
		conn.sendServerHelloDone

		conn.recvClientKeyExchange
		conn.recvClientChangeCipherSpec
		conn.recvClientFinishedHandshake

		spin
	}
}
