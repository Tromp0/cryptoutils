package cat.uvic.teknos.m09.tomaslopez.cryptoutils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

import static java.security.cert.CertificateFactory.getInstance;

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
    //  SIGN AND VERIFY METHODS //
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

    public static boolean verify (byte[]  message, byte[] signature, byte[] certificate) throws SignatureException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, IOException {
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        var signer = Signature.getInstance(properties.getProperty("keystore.algorithm"));
        var certFactory = getInstance("X.509");
        InputStream inptStream = new ByteArrayInputStream(certificate);
        var cert = (X509Certificate)certFactory.generateCertificate(inptStream); cert = null;
        cert.checkValidity();
        var publicKey = cert.getPublicKey();
        signer.initVerify(publicKey);
        signer.update(message);

        return signer.verify(signature);

    }
    //  ENCRYPT AND DECRYPT METHODS //
    public static byte[] encrypt(String text, String pw) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var textBytes = text.getBytes();
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        hashSalt = getSalt();
        var ivP = new IvParameterSpec(hashSalt);
        var pbeKeySpec = new PBEKeySpec(pw.toCharArray(), hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        var pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");
        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivP);

        return cipher.doFinal(textBytes);
    }
    public static byte[] decrypt(byte[] cipherText, String pw) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(Cryptoutils.class.getResourceAsStream("/cryptoutils.properties"));
        var iv = new IvParameterSpec(hashSalt);
        var pbeKeySpec = new PBEKeySpec(pw.toCharArray(),hashSalt, Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        var pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");
        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(cipherText);
    }

}
