# tls-spring-security


# (used to generate keystore)
keytool -genkeypair -alias tcserver -storetype JKS -keystore serverkeystore.jks
-keyalg RSA -keysize 2048 -keypass topsecret -storepass topsecret
