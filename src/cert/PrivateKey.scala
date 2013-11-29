package cert

import scala.io._
import util.Util._
import util.Base64

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

	def parsePem(pemstr: String) {
		val ind_prefix = pemstr.indexOf(prefix_mark)
		val ind_postfix = pemstr.indexOf(postfix_mark)
	
		assert(ind_prefix >= 0)
		assert(ind_postfix >= 0)

		val body = pemstr.substring(ind_prefix + prefix_mark.length, ind_postfix)
		val der = Base64.decode(body)
		dumpByteArray(der)
	}
}
