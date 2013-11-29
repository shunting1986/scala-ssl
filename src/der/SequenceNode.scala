package der

import util.ArrayBasedReader

class SequenceNode extends DerNode {
	var nodeList = List[DerNode]()
	
	override def decode(reader: ArrayBasedReader): DerNode = {
		val len = decodeLength(reader)
		val subreader = new ArrayBasedReader(reader.nextBytes(len))
		while (subreader.hasMore) {
			val optid = subreader.peekInt(1)
			if ((optid & 0xe0) == 0xa0) {
				printf("[SEQID %04x]\n", subreader.nextInt(2))
			}
			nodeList = nodeList :+ DerNode.decode(subreader)
		}
		this
	} 

	override def dump(ind: Int) {
		doIndent(ind)
		printf("[SEQUENCE]\n")
		for (node <- nodeList) {
			node.dump(ind + 2)
		}
	}
}
