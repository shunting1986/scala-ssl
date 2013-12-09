scala-ssl
=========

A SSL Client and Server written in Scala

This project contains a runnable SSL Client and SSL Server. The client can be used to talk to tomcat.
The server can be used to talk to 'openssl s_client'. Of course, the client can be used to talk to the server:)

The project builds everything from scratch. And it can give you the details about the workflow of SSL.

The project is quite simple right now. At least the following things can be done to improve it:
1. Only support one cipher suite SSL_RSA_WITH_RC4_128_MD5, need supports more
2. Does not verify server certificat right now
3. Does not support certificate chain right now
4. Does not support client certificate
5. Does not support ssl session
6. The style is more like imperative programming rather than functional programming in some of the code
7. ...
