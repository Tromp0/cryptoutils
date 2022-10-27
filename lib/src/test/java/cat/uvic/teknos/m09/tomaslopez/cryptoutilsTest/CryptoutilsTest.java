package cat.uvic.teknos.m09.tomaslopez.cryptoutilsTest;

import cat.uvic.teknos.m09.tomaslopez.crypyoutils.Cryptoutils;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class CryptoutilsTest {
    @Test
    public void hash() throws IOException, NoSuchAlgorithmException {
        var bytes = "EXAMPLE TEXT".getBytes();
        Cryptoutils.getHash(bytes);
    }
}
