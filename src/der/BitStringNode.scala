package der

import util._
import util.Util._

class BitStringNode extends DerNode {
	var unused = 0
	var data = Array[Byte]()

	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader);
		assert(len > 0)
		unused = reader.nextInt(1)
		data = reader.nextBytes(len - 1)
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[BitString] unused %d, data:\n", unused)
		dumpByteArray(data)
	}
}
