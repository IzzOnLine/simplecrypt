package it.izzonline.simplecrypt;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Simplecrypt {

	private static final String AES = "AES";

	public String encrypt(final String clearText, final String key) throws Exception {
		Key aesKey = new SecretKeySpec(key.getBytes(), AES);
		Cipher cipher = Cipher.getInstance(AES);
		cipher.init(Cipher.ENCRYPT_MODE, aesKey);
		byte[] encrypted = cipher.doFinal(clearText.getBytes());
		return new String(Base64.encodeBase64(encrypted));
	}

	public String decrypt(final String encryptedText, final String key) throws Exception {
		Cipher cipher = Cipher.getInstance(AES);
		Key aesKey = new SecretKeySpec(key.getBytes(), AES);
		cipher.init(Cipher.DECRYPT_MODE, aesKey);
		String decrypted = new String(cipher.doFinal(Base64.decodeBase64(encryptedText.getBytes())));
		return decrypted;
	}

}
