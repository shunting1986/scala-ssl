package der

import util._

class UTCTimeNode extends DerNode {
	var data = Array[Byte]()

	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		data = reader.nextBytes(len);
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[UTCTime]: %s\n", new String(data))
	}
}
