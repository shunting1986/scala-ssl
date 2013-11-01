package util

import util.Util._

class ArrayBasedReader(_data: Array[Byte]) {
	private var data = _data

	def hasMore(): Boolean = {
		data.length > 0
	}

	def nextInt(len: Int): Int = {
		byteArrayToInt(nextBytes(len))
	}

	def nextBytes(len: Int): Array[Byte] = {
		assert(data.length >= len)
		val subdata = data.dropRight(data.length - len)
		data = data.drop(len)
		subdata
	}

	def getData(): Array[Byte] = data
}
