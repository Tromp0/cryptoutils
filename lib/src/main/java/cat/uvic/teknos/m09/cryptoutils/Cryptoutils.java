package cat.uvic.teknos.m09.cryptoutils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Cryptoutils {

    public static String getDigestNoSalt(String data) throws NoSuchAlgorithmException {
        var dataBytes = data.getBytes();

        var messageDigest = MessageDigest.getInstance("SHA-256");

        var digest = messageDigest.digest(dataBytes);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static String getDigest(String data, byte[] salt) throws NoSuchAlgorithmException {
        var dataBytes = data.getBytes();

        var messageDigest = MessageDigest.getInstance("SHA-256");

        messageDigest.update(salt);
        var digest = messageDigest.digest(dataBytes);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static byte[] getSalt() {
        var secureRandom = new SecureRandom();

        var salt = new byte[16];
        secureRandom.nextBytes(salt);

        return salt;
    }
}
