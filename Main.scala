import java.net.Socket
import java.io.OutputStream

def sendMessage(host: String, port: Int, msg: Array[Byte]) {
	val sock = new Socket(host, port)
	val os = sock.getOutputStream
	os.write(msg)
}

sendMessage("localhost", 1234, "abc".getBytes)
