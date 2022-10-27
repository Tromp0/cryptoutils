package cat.uvic.teknos.m09.tomaslopez.cryptoutils;

import junit.framework.TestCase;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CryptoutilsTest extends TestCase {
    @Test
    public void getHash() throws IOException, NoSuchAlgorithmException {
        var msg = "EXAMPLE TEXT";
        assertTrue(Cryptoutils.getHash(msg)!="");
    }
    @Test
    public void sign() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        var message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        assertNotNull(Cryptoutils.sign(message));
    }
    @Test
    public void verify() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        var message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));
        var certificate = Files.readAllBytes(Paths.get("src/main/resources/certificate.cer"));
        assertNotNull(Cryptoutils.verify(message,Cryptoutils.sign(message),certificate));
    }
    @Test
    public void encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String myvar = "EXAMPLE TEXT";
        assertNotNull(Cryptoutils.encrypt(myvar,"1999"));
    }
    @Test
    public void decrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String myvar = "EXAMPLE TEXT";
        byte [] encrypted = Cryptoutils.encrypt(myvar,"1999");
        assertNotNull(Cryptoutils.decrypt(encrypted,"1999"));

    }
}
