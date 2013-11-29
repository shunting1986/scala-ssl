package cert

import scala.io._
import util.Util._
import util.Base64
import der._

object PrivateKey {
	def main(args: Array[String]) {
		assert(args.length > 0)

		val keyPath = args(0)

		val fcont = Source.fromFile(keyPath).getLines.mkString("\n")
		val rkey = new PrivateKey
		rkey.parsePem(fcont)
	}
}

class PrivateKey {
	val prefix_mark = "-----BEGIN RSA PRIVATE KEY-----";
	val postfix_mark = "-----END RSA PRIVATE KEY-----";

  /*
   RSAPrivateKey ::= SEQUENCE {
     version Version,
     modulus INTEGER, -- n
     publicExponent INTEGER, -- e
     privateExponent INTEGER, -- d
     prime1 INTEGER, -- p
     prime2 INTEGER, -- q
     exponent1 INTEGER, -- d mod (p-1)
     exponent2 INTEGER, -- d mod (q-1)
     coefficient INTEGER -- (inverse of q) mod p }
   */

	var modulus: BigInt = 0
	var publicExponent: BigInt = 0
	var privateExponent: BigInt = 0
	
	def setFields(node: DerNode) {
		val seq = node.asInstanceOf[SequenceNode]
		val nodeList = seq.nodeList
		
		// modulus
		modulus = nodeList(1).asInstanceOf[IntegerNode].value
		// publicExponent
		publicExponent = nodeList(2).asInstanceOf[IntegerNode].value
		// privateExponent
		privateExponent = nodeList(3).asInstanceOf[IntegerNode].value
	}

	def validate(node: DerNode) {
		assert(node.isInstanceOf[SequenceNode])
		val seq = node.asInstanceOf[SequenceNode]
		assert(seq.length == 9)
	}

	def parsePem(pemstr: String) {
		val ind_prefix = pemstr.indexOf(prefix_mark)
		val ind_postfix = pemstr.indexOf(postfix_mark)
	
		assert(ind_prefix >= 0)
		assert(ind_postfix >= 0)

		val body = pemstr.substring(ind_prefix + prefix_mark.length, ind_postfix)
		val der = Base64.decode(body)

		val node = DerNode.decode(der)
		validate(node)
		setFields(node)
	}
}
