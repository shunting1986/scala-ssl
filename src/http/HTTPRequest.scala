package http

import util.Util._

class HTTPRequest(_requestStr: String) {
	var requestStr = _requestStr
	var method = ""
	var uri = ""
	var version = ""

	// do initialize
	val dummy = {
		requestStr = requestStr.trim
		
		var i = 0
		var compList = Vector[String]()
		while (i < requestStr.length && requestStr(i) != '\r' && requestStr(i) != '\n') {
			while (i < requestStr.length && isSpace(requestStr(i))) {
				i += 1
			}

			val anchor = i
			while(i < requestStr.length && !isSpace(requestStr(i))) {
				i += 1
			}

			if (anchor < requestStr.length) {
				compList = compList :+ requestStr.substring(anchor, i)
			}
		}
		assert(compList.length == 3)
		method = compList(0)
		uri = compList(1)
		version = compList(2)
	}
}
