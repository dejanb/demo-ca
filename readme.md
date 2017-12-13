https://jamielinux.com/docs/openssl-certificate-authority/

openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/client-1.key.pem \
      -new -sha256 -out intermediate/csr/client-1-1.csr.pem

openssl ca -config intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/client-1-1.csr.pem \
      -out intermediate/certs/client-1-1.cert.pem


openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/client-1.key.pem \
      -new -sha256 -out intermediate/csr/client-1-3.csr.pem      

openssl ca -config intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/client-1-3.csr.pem \
      -out intermediate/certs/client-1-3.cert.pem      



openssl pkcs12 -export -in intermediate/certs/broker.cert.pem -inkey intermediate/private/broker.key.pem > broker.p12
keytool -importkeystore -srckeystore broker.p12 -destkeystore broker.ks -srcstoretype pkcs12
rm broker.p12

openssl pkcs12 -export -in intermediate/certs/client-1-1.cert.pem -inkey intermediate/private/client-1.key.pem > client-1-1.p12
keytool -importkeystore -srckeystore client-1-1.p12 -destkeystore client-1-1.ks -srcstoretype pkcs12
rm client-1-1.p12



keytool -import -file intermediate/certs/client-1-1.cert.pem -alias client-1-1 -trustcacerts -keystore broker.ts
keytool -import -file intermediate/certs/ca-chain.cert.pem -alias CA -trustcacerts -keystore broker.ts
keytool -import -file intermediate/certs/broker.cert.pem -alias broker -trustcacerts -keystore client-1-1.ts
keytool -import -file intermediate/certs/ca-chain.cert.pem -alias CA -trustcacerts -keystore client-1-1.ts


OCSP

openssl genrsa -aes256 \
      -out intermediate/private/ocsp.key.pem 4096

openssl req -config intermediate/openssl.cnf -new -sha256 \
      -key intermediate/private/ocsp.key.pem \
      -out intermediate/csr/ocsp.csr.pem

openssl ca -config intermediate/openssl.cnf \
      -extensions ocsp -days 375 -notext -md sha256 \
      -in intermediate/csr/ocsp.csr.pem \
      -out intermediate/certs/ocsp.cert.pem      

openssl ocsp -port 2560 \
      -index intermediate/index.txt \
      -CA intermediate/certs/ca-chain.cert.pem \
      -rkey intermediate/private/ocsp.key.pem \
      -rsigner intermediate/certs/ocsp.cert.pem

openssl ocsp -CAfile intermediate/certs/ca-chain.cert.pem \
      -url http://127.0.0.1:2560 -resp_text \
      -issuer intermediate/certs/intermediate.cert.pem \
      -cert intermediate/certs/client-1-1.cert.pem      
     

export ACTIVEMQ_SSL_OPTS="-Dcom.sun.security.enableCRLDP=true -Docsp.enable=true -Docsp.responderURL=http://localhost:2560"     


Revoke

openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/client-1.key.pem \
      -new -sha256 -out intermediate/csr/client-1-2.csr.pem

openssl ca -config intermediate/openssl.cnf \
      -extensions usr_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/client-1-2.csr.pem \
      -out intermediate/certs/client-1-2.cert.pem      

openssl pkcs12 -export -in intermediate/certs/client-1-2.cert.pem -inkey intermediate/private/client-1.key.pem > client-1-2.p12      
keytool -importkeystore -srckeystore client-1-2.p12 -destkeystore client-1-2.ks -srcstoretype pkcs12
rm client-1-2.p12
keytool -import -file intermediate/certs/client-1-2.cert.pem -alias client-1-2 -trustcacerts -keystore broker.ts
keytool -import -file intermediate/certs/broker.cert.pem -alias broker -trustcacerts -keystore client-1-2.ts
keytool -import -file intermediate/certs/ca-chain.cert.pem -alias CA -trustcacerts -keystore client-1-2.ts


openssl ca -config intermediate/openssl.cnf \
      -revoke intermediate/certs/client-1-2.pem

/workspace/oss/mq/activemq/assembly/target/apache-activemq-5.14-SNAPSHOT//bin/activemq console xbean:org/apache/activemq/security/activemq-revoke.xml

/workspace/oss/mq/activemq/assembly/target/apache-activemq-5.14-SNAPSHOT/bin/activemq -Djavax.net.ssl.keyStore=org/apache/activemq/security/activemq-revoke.jks -Djavax.net.ssl.keyStorePassword=password \
-Djavax.net.ssl.trustStore=org/apache/activemq/security/client.ts -Djavax.net.ssl.trustStorePassword=password \
consumer --brokerUrl ssl://localhost:61617

/workspace/oss/mq/activemq/assembly/target/apache-activemq-5.14-SNAPSHOT/bin/activemq \
-Djavax.net.ssl.keyStore=client-1-3.ks -Djavax.net.ssl.keyStorePassword=activemq \
-Djavax.net.ssl.trustStore=client-1-3.ts -Djavax.net.ssl.trustStorePassword=activemq \
consumer --brokerUrl ssl://localhost:61617

keytool -import -file intermediate/certs/client-1-3.cert.pem -alias client-1-3 -trustcacerts -keystore broker.ts
