package http

class HTTPResponse(body: String) {
	def serialize = {
		"""|HTTP/1.0 200 OK
		|
		|""".stripMargin + body
	}
}
