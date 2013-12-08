import java.net.ServerSocket
import util.Util._

object SSLServer {
	def main(args: Array[String]) {
		val listenSock = new ServerSocket(8888)

		printf("Waiting for connect...\n")
		val workSock = listenSock.accept

		// conn.recvClientHello

		spin
	}
}
