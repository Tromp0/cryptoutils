package cat.uvic.teknos.m09.tomaslopez.crypyoutils;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

public class Cryptoutils {

    // HASHING METHODS //
    public static String getHash(byte[] message) throws IOException, NoSuchAlgorithmException {
        var encryptedmsg = "";
        var propieties = new Properties();
        propieties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.propieties"));
        var hashAlgorithm = propieties.getProperty("hash.algorithm");
        if(Boolean.parseBoolean((String) propieties.get("hash.salt"))){
            var salt = getSalt();
            encryptedmsg = getDigest(message, salt, hashAlgorithm);
        }
        else{
            encryptedmsg = getDigestNoSalt(message, hashAlgorithm);
        }
        return encryptedmsg;
    }

    public static String getDigestNoSalt(byte[] data, String algorithm) throws NoSuchAlgorithmException {
        var dataBytes = data;

        var messageDigest = MessageDigest.getInstance(algorithm);

        var digest = messageDigest.digest(dataBytes);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static String getDigest(byte[] data, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        var dataBytes = data;

        var messageDigest = MessageDigest.getInstance(algorithm);

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
    //  ENCRYPT AND DECRYPT METHODS //
    public byte[] singDocument(){

        return new byte[0];
    }

}
