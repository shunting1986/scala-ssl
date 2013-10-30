import java.net.Socket
import java.io.OutputStream

import scala.util.Random

def HANDSHAKE: Byte = 0x16
def MAJVER: Byte = 0x03
def MINVER: Byte = 0x00

def CLIENT_HELLO: Byte = 0x01

def SSL_RSA_WITH_RC4_128_MD5 = 0x04
def NULL_COMPRESS = 0x00

def intToByteArray(value: Int, len: Int): Array[Byte] = {
	if (len == 0) {
		Array[Byte]()
	} else {
		intToByteArray(value / 256, len - 1) :+ (value % 256).asInstanceOf[Byte]
	}
}

def toHandshake(msg: Array[Byte]) : Array[Byte] = {
	Array[Byte](HANDSHAKE, MAJVER, MINVER) ++ intToByteArray(msg.length, 2) ++ msg
}

def spin() {
	while (true) {
		print(".")
		Thread.sleep(1000)
	}
}

def sendMessage(host: String, port: Int, msg: Array[Byte]) {
	val sock = new Socket(host, port)
	val os = sock.getOutputStream
	os.write(msg)
	spin
}

def cipherSuiteList: Array[Byte] = {
	val cs = intToByteArray(SSL_RSA_WITH_RC4_128_MD5, 2)
	intToByteArray(cs.length, 2) ++ cs
}

def compressMethodList: Array[Byte] = {
	val cm = intToByteArray(NULL_COMPRESS, 1)
	intToByteArray(cm.length, 1) ++ cm
}

def genRandom(len: Int): Array[Byte] = {
	val a = new Array[Byte](len)
	Random.nextBytes(a)
	a
}

def genClientHello(): Array[Byte] = {
	// CLIENT_HELLO byte ++ size (3 bytes) ++ vmaj ++ vmin ++ random (32 bytes) ++ session id (length + content) ++ cipher suite list (len_16 && list) 
	//   ++ compress method list (len_8 && list)
	val payload = Array[Byte](MAJVER, MINVER) ++ genRandom(32) ++ Array[Byte](0) ++ cipherSuiteList ++ compressMethodList
	Array[Byte](CLIENT_HELLO) ++ intToByteArray(payload.length, 3) ++ payload
}

val msg = toHandshake(genClientHello())
val host = "127.0.0.1"
// val port = 1234
val port = 8443
sendMessage(host, port, msg)

