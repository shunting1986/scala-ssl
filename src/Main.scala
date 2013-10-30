import java.net.Socket
import java.io.OutputStream
import java.io.InputStream

import scala.util.Random

def HANDSHAKE: Byte = 0x16
def MAJVER: Byte = 0x03
def MINVER: Byte = 0x00

def CLIENT_HELLO: Byte = 0x01

def SSL_RSA_WITH_RC4_128_MD5 = 0x04
def NULL_COMPRESS = 0x00

class StreamBasedArray(stream: InputStream) {
	var internalArray = Array[Byte]()

	/* always return the next len bytes. abort if not enough bytes in the stream */
	def nextBytes(len: Int): Array[Byte] = {
		if (internalArray.length >= len) {
			val ret = internalArray.dropRight(internalArray.length - len)
			internalArray = internalArray.drop(len)
			ret
		} else {
			readMore(len - internalArray.length)
			nextBytes(len)
		}
	}

	def readMore(len: Int) {
		val buf = new Array[Byte](len)
		val n = stream.read(buf)
		if (n == -1)
			sys.error("EOF too early")
		internalArray = internalArray ++ buf.dropRight(len - n)
		if (n < len)
			readMore(len - n)
	}
}

def dumpByteArray(bin: Array[Byte]) {
	def width = 16
	def dumpLine(subbin: Array[Byte]) {
		if (subbin.length == 0) 
			println("")
		else {
			printf(" %02x", subbin(0))
			dumpLine(subbin.drop(1))
		}
	}
	if (bin.length <= width) {
		dumpLine(bin)
	} else {
		dumpLine(bin.dropRight(bin.length - width)) 
		dumpByteArray(bin.drop(width))
	}
}

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

	val sbArray = new StreamBasedArray(sock.getInputStream)
	dumpByteArray(sbArray.nextBytes(64))

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

def run {
	val msg = toHandshake(genClientHello())
	val host = "127.0.0.1"
	// val port = 1234
	val port = 8443
	sendMessage(host, port, msg)
}

run
