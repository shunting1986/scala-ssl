package util

import java.io.InputStream

/* wrap an input stream as an array */
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

	private def readMore(len: Int) {
		val buf = new Array[Byte](len)
		val n = stream.read(buf)
		if (n == -1)
			sys.error("EOF too early")
		internalArray = internalArray ++ buf.dropRight(len - n)
		if (n < len)
			readMore(len - n)
	}
}

