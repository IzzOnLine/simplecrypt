package it.izzonline.simplecrypt;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Simplecrypt {

	private static final String AES = "AES";
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final byte[] IV = { 3, 0, 0, 6, 1, 9, 8, 0, 1, 2, 0, 9, 7, 6, 6, 6 };

	public static String encrypt(final String clearText, final SecretKey key) throws Exception {
		IvParameterSpec ivspec = new IvParameterSpec(IV);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
		byte[] encrypted = cipher.doFinal(clearText.getBytes());
		return new String(Base64.encodeBase64(encrypted));
	}

	public static String decrypt(final String encryptedText, final SecretKey key) throws Exception {
		SecretKeySpec spec = new SecretKeySpec(key.getEncoded(), AES);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		IvParameterSpec ivspec = new IvParameterSpec(IV);
		cipher.init(Cipher.DECRYPT_MODE, spec, ivspec);
		String decrypted = new String(cipher.doFinal(Base64.decodeBase64(encryptedText.getBytes())));
		return decrypted;
	}

	public static SecretKey generateKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(128);
		SecretKey key = keyGenerator.generateKey();
		return key;
	}

}
