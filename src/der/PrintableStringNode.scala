package der

import util._

class PrintableStringNode extends DerNode {
	var s: String = null
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		val data = reader.nextBytes(len)
		s = new String(data)
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[PrintableString]: %s\n", s)
	}
}
