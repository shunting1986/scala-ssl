package der

import util.ArrayBasedReader

object DerNode {
	def decode(bin: Array[Byte]): DerNode = {
		val reader = new ArrayBasedReader(bin)
		val node = decode(reader)
		assert(!reader.hasMore)
		node
	}
	
	def decode(reader: ArrayBasedReader): DerNode = {
		val typeByte = reader.nextInt(1)

		if (typeByte == 0x30) { // sequence 
			(new SequenceNode).decode(reader)
		} else if (typeByte == 0x02) { // integer
			(new IntegerNode).decode(reader)
		} else {
			printf("type is 0x%02x\n", typeByte)
			sys.error("unsupported ASN.1 type")
			null
		}
	}
}

abstract class DerNode {
	/*
	 * Decode the byte sequence in reader and construct the DerNode.
	 * The reader may have some bytes left
	 *
	 * Reader the node itself
	 */
	def decode(reader: ArrayBasedReader): DerNode = {
		assert(false); null
	}

	def dump(ind: Int) {
		assert(false)
	}

	def doIndent(ind: Int) {
		var i = 0
		while (i < ind) {
			printf(" ")
			i += 1
		}
	}

	def decodeLength(reader: ArrayBasedReader): Int = {
		var first = reader.nextInt(1)
		if ((first & 0x80) != 0) {
			first = first & ~0x80
			reader.nextInt(first)
		} else {
			first	
		}
	}
}
