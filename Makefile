SCALA_BIN_DIR := /home/shunting/work/ubuntu-contents/learn-lang/lang/scala/scala-2.10.2/bin
SCALA := $(SCALA_BIN_DIR)/scala
SCALAC := $(SCALA_BIN_DIR)/scalac

compile:
	find src -name *.scala | xargs $(SCALAC) -d classes

client:
	@#$(SCALA) -classpath classes SSLClient 127.0.0.1 8443 # for tomcat
	@$(SCALA) -classpath classes SSLClient 127.0.0.1 8888 # for SSLServer

openssl_client:
	openssl s_client -host 127.0.0.1 -port 8888 -ssl3 -cipher RC4-MD5

curl_client:
	curl -k3 "https://localhost:8888/from-curl"

server:
	@$(SCALA) -classpath classes SSLServer /home/shunting/work/ubuntu-contents/learn-lang/proj/ssl/certs/server.crt /home/shunting/work/ubuntu-contents/learn-lang/proj/ssl/certs/server.key 8888
 

