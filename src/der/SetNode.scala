package der

import util._

class SetNode extends DerNode {
	var nodeList = Vector[DerNode]()

	// NOTE: the same as sequence?
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		val subreader = new ArrayBasedReader(reader.nextBytes(len))
		while (subreader.hasMore) {
			nodeList = nodeList :+ DerNode.decode(subreader)
		}
		this
	}

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[SET]\n")
		for (node <- nodeList) {
			node.dump(ind + 2)
		}
	}
}
