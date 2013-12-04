package crypto

abstract class Hash {
	def doHash(input: Array[Byte]): Array[Byte]
}
