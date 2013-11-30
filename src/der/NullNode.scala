package der

import util.ArrayBasedReader

class NullNode extends DerNode {
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		assert(len == 0)
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[NULL]\n")
	}
}
