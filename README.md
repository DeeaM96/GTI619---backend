
# GTI 619 LAB 5 - API



## Prérequis

- JDK 17
- IDE de votre choix (par exemple, IntelliJ IDEA)


## Démarrage de l'Application

Pour démarrer l'application en utilisant Maven, exécutez :

```bash
./mvnw spring-boot:run
```

Ou si vous utilisez Gradle :

```bash
./gradlew bootRun
```

POur le certificat, il faut generer un nouveau certificat pour votre machine: 

1. Installer mkcert 
2.  `mkcert -install`
3. `mkcert localhost`
4. `openssl pkcs12 -export -in localhost.pem -inkey localhost-key.pem -out keystore.p12 -name localhost -CAfile "$(mkcert -CAROOT)/rootCA.pem" -caname root
   `

