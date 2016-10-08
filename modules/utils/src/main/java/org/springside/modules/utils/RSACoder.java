package org.springside.modules.utils;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lining on 16/6/30.
 */
public class RSACoder {

	public static final String RSA = "RSA";
	public static final String PUBLIC_KEY = "RSAPublicKey";
	public static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * 私钥解密
	 * @param data
	 * @param key
	 * @return
	 */
	public static byte[] decryptByPriKey(byte[] data, byte[] key) {
		// 获取私钥
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 公钥解密
	 * @param data
	 * @param key
	 * @return
	 */
	public static byte[] decryptByPubKey(byte[] data, byte[] key) {
		// 获取公钥
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 公钥加密
	 * @param data
	 * @param key
	 * @return
	 */
	public static byte[] encryptByPubKey(byte[] data, byte[] key) {
		// 获取公钥
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 私钥加密
	 * @param data
	 * @param key
	 * @return
	 */
	public static byte[] encryptByPriKey(byte[] data, byte[] key) {
		// 获取私钥
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(RSA);
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
			throw Exceptions.unchecked(e);
		}
	}

	public static Map<String, RSAKey> initKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPrivateKey aPrivate = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();

		Map<String, RSAKey> keys = new HashMap<>();
		keys.put(PRIVATE_KEY, aPrivate);
		keys.put(PUBLIC_KEY, aPublic);
		return keys;
	}

}
