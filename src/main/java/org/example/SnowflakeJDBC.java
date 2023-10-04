package org.example;

import java.io.FileReader;
import java.security.PrivateKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class SnowflakeJDBC {

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: java SnowflakeJDBCExampleWithArgs <url> <username> <privateKeyPath> <privateKeyPassphrase>");
            System.exit(1);
        }

        String url = args[0];
        String user = args[1];
        String privateKeyPath = args[2];
        String privateKeyPassphrase = args[3];
        
        Properties properties = new Properties();
        properties.put("user", user);
        properties.put("privateKey", getPrivateKey(privateKeyPath, privateKeyPassphrase));
        properties.put("db", "testdb");
        properties.put("schema", "public");

        try (Connection connection = DriverManager.getConnection(url, properties)) {
            System.out.println("Successfully connected to Snowflake!");
            // Your database related operations go here
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("Unable to connect to Snowflake: " + e.getMessage());
        }
    }

    private static PrivateKey getPrivateKey(String filePath, String passphrase) {
        try (PEMParser pemParser = new PEMParser(new FileReader(filePath))) {
            Object object = pemParser.readObject();
            
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            
            if (object instanceof PEMEncryptedKeyPair) {
                return converter.getPrivateKey(
                    ((PEMEncryptedKeyPair) object).decryptKeyPair(
                        new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray())
                    ).getPrivateKeyInfo()
                );
            } else {
                return converter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to load private key: " + e.getMessage(), e);
        }
    }
}
