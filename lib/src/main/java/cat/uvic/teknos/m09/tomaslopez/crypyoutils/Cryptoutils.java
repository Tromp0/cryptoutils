package cat.uvic.teknos.m09.tomaslopez.crypyoutils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

public class Cryptoutils {

    private static byte[] hashSalt;

    // HASHING METHODS //
    public static String getHash(String message) throws IOException, NoSuchAlgorithmException {
        var messagebytes = message.getBytes();
        var encryptedmsg = "";
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.propieties"));
        var hashAlgorithm = properties.getProperty("hash.algorithm");
        if(Boolean.parseBoolean((String) properties.get("hash.salt"))){
            var salt = getSalt();
            encryptedmsg = getDigest(messagebytes, salt, hashAlgorithm);
        }
        else{
            encryptedmsg = getDigestNoSalt(messagebytes, hashAlgorithm);
        }
        return encryptedmsg;
    }
    public static String getDigestNoSalt(byte[] dataBytes, String algorithm) throws NoSuchAlgorithmException {

        var messageDigest = MessageDigest.getInstance(algorithm);
        var digest = messageDigest.digest(dataBytes);
        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    public static String getDigest(byte[] dataBytes, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
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
    public static byte[] encrypt(String text, String pw) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var textBytes = text.getBytes();
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.propieties"));
        hashSalt = getSalt();
        var iv = new IvParameterSpec(hashSalt);
        var pbeKeySpec = new PBEKeySpec(pw.toCharArray(), hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        var pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");
        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(textBytes);
    }
    public static byte[] decrypt(byte[] cipherText, String pw) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        var base64Encoder = Base64.getEncoder();
        var iv = new IvParameterSpec(hashSalt);
        var pbeKeySpec = new PBEKeySpec(pw.toCharArray(),hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        var pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");
        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(cipherText);

    }
    public static byte[] sign (byte[] message) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(properties.getProperty("keystore.name")), properties.getProperty("keystore.password").toCharArray());
        var privateKey = keystore.getKey(properties.getProperty("keystore.alias"),properties.getProperty("keystore.password").toCharArray());
        var signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));
        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        return signer.sign();



    }

}
