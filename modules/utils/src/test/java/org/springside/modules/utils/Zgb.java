package org.springside.modules.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 * Created by lining on 2016/8/2.
 */
public class Zgb {

	private static final String AESKEY = "com.jd.lbs";

	public static String decryptAES(String srcStr) {
		return decryptAES(srcStr, "com.jd.lbs");
	}

	private static String decryptAES(String srcStr, String key) {
		try {
			byte[] e = parseToBytes(srcStr);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(2, getKey(key));
			return new String(cipher.doFinal(e), Charset.defaultCharset());
		} catch (Exception var4) {
			throw new RuntimeException("初始化应用ID信息异常");
		}
	}

	private static byte[] parseToBytes(String src) {
		byte[] resBytes = new byte[src.length() / 2];

		for(int i = 0; i < resBytes.length; ++i) {
			Integer highPlace = Integer.valueOf(Integer.parseInt(src.substring(i * 2, i * 2 + 1), 16));
			Integer lowPlace = Integer.valueOf(Integer.parseInt(src.substring(i * 2 + 1, (i + 1) * 2), 16));
			resBytes[i] = (byte)(highPlace.intValue() * 16 + lowPlace.intValue());
		}

		return resBytes;
	}

	private static SecretKey getKey(String key) {
		try {
			KeyGenerator e = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(key.getBytes());
			e.init(128, secureRandom);
			return e.generateKey();
		} catch (Exception var3) {
			throw new RuntimeException("初始化应用ID信息异常");
		}
	}

	private static void encrypt(String input) {
		SecretKey key = getKey(AESKEY);

		byte[] encryptResult = Cryptos.aesEncrypt(input.getBytes(), key.getEncoded());
//		String descryptResult = Cryptos.aesDecrypt(encryptResult, key.getEncoded());

		System.out.println("zgb :" + Encodes.encodeHex(encryptResult));
	}

	public static void main(String[] args) {
		encrypt("51020");
	}
}
