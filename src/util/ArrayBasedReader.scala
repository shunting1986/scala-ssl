package util

import util.Util._

class ArrayBasedReader(_data: Array[Byte]) {
	private var data = _data

	def hasMore(): Boolean = {
		data.length > 0
	}

	def peekInt(len: Int): Int = {
		byteArrayToInt(peekBytes(len))
	}

	def peekBytes(len: Int): Array[Byte] = {
		assert(data.length >= len)
		data.dropRight(data.length - len)
	}
	
	def skip(len: Int) {
		data = data.drop(len)
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

	def leftLength = data.length

	def getData(): Array[Byte] = data
}
