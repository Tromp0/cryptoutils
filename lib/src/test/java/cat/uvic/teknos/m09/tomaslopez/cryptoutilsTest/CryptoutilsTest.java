package cat.uvic.teknos.m09.tomaslopez.cryptoutilsTest;

import cat.uvic.teknos.m09.tomaslopez.crypyoutils.Cryptoutils;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CryptoutilsTest {
    @Test
    public void getHash() throws IOException, NoSuchAlgorithmException {
        var msg = "EXAMPLE TEXT";
        assertTrue(Cryptoutils.getHash(msg)!="");
    }
    @Test
    void encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String myvar = "Any String you want";
        assertNotNull(Cryptoutils.encrypt(myvar,"1234"));
    }
    @Test
    void decrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String myvar = "Any String you want";
        byte [] encrypted = Cryptoutils.encrypt(myvar,"1234");
        assertNotNull(Cryptoutils.decrypt(encrypted,"1234"));

    }
    @Test
    void sign() throws IOException {
        byte[] message = new byte[0];
        message = Files.readAllBytes(Paths.get("src/main/resources/message.txt"));

        assertNotNull(Cryptoutils.sign(message));
    }
}
