/*******************************************************************************
 * Copyright (c) 2005, 2014 springside.github.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *******************************************************************************/
package org.springside.modules.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * 支持HMAC-SHA1消息签名 及 DES/AES对称加密的工具类.
 * 
 * 支持Hex与Base64两种编码方式.
 * 
 * @author calvin
 */
public class Cryptos {

	private static final String AES = "AES";
	private static final String DES = "DES";
	private static final String AES_CBC = "AES/CBC/PKCS5Padding";
	private static final String DES_ECB = "DES/ECB/PKCS5Padding";
	private static final String HMACSHA1 = "HmacSHA1";

	private static final int DEFAULT_HMACSHA1_KEYSIZE = 160; // RFC2401
	private static final int DEFAULT_AES_KEYSIZE = 128;
	private static final int DEFAULT_DES_KEYSIZE = 56;
	private static final int DEFAULT_IVSIZE = 16;

	private static SecureRandom random = new SecureRandom();

	// -- HMAC-SHA1 funciton --//
	/**
	 * 使用HMAC-SHA1进行消息签名, 返回字节数组,长度为20字节.
	 * 
	 * @param input 原始输入字符数组
	 * @param key HMAC-SHA1密钥
	 */
	public static byte[] hmacSha1(byte[] input, byte[] key) {
		try {
			SecretKey secretKey = new SecretKeySpec(key, HMACSHA1);
			Mac mac = Mac.getInstance(HMACSHA1);
			mac.init(secretKey);
			return mac.doFinal(input);
		} catch (GeneralSecurityException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 校验HMAC-SHA1签名是否正确.
	 * 
	 * @param expected 已存在的签名
	 * @param input 原始输入字符串
	 * @param key 密钥
	 */
	public static boolean isMacValid(byte[] expected, byte[] input, byte[] key) {
		byte[] actual = hmacSha1(input, key);
		return Arrays.equals(expected, actual);
	}

	/**
	 * 生成HMAC-SHA1密钥,返回字节数组,长度为160位(20字节).
	 * HMAC-SHA1算法对密钥无特殊要求, RFC2401建议最少长度为160位(20字节).
	 */
	public static byte[] generateHmacSha1Key() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(HMACSHA1);
			keyGenerator.init(DEFAULT_HMACSHA1_KEYSIZE);
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey.getEncoded();
		} catch (GeneralSecurityException e) {
			throw Exceptions.unchecked(e);
		}
	}

	// -- AES funciton --//
	/**
	 * 使用AES加密原始字符串.
	 * 
	 * @param input 原始输入字符数组
	 * @param key 符合AES要求的密钥
	 */
	public static byte[] aesEncrypt(byte[] input, byte[] key) {
		return aes(input, key, Cipher.ENCRYPT_MODE);
	}

	/**
	 * 使用AES加密原始字符串.
	 * 
	 * @param input 原始输入字符数组
	 * @param key 符合AES要求的密钥
	 * @param iv 初始向量
	 */
	public static byte[] aesEncrypt(byte[] input, byte[] key, byte[] iv) {
		return aes(input, key, iv, Cipher.ENCRYPT_MODE);
	}

	/**
	 * DES 加密
	 * @param data, 原始数据, 字节数组形式
	 * @param key, 原始密钥, 字节数组
	 * @return 加密后数据, 字节数组形式
	 */
	public static byte[] desEncrypt(byte[] data, byte[] key) {
		// 还原二进制密钥为密钥对象
		Key k = generateDesKey(key);
		try {
			// 初始化, 设置为加密模式
			Cipher cipher = Cipher.getInstance(DES_ECB);
			cipher.init(Cipher.ENCRYPT_MODE, k);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 使用AES解密字符串, 返回原始字符串.
	 * 
	 * @param input Hex编码的加密字符串
	 * @param key 符合AES要求的密钥
	 */
	public static String aesDecrypt(byte[] input, byte[] key) {
		byte[] decryptResult = aes(input, key, Cipher.DECRYPT_MODE);
		return new String(decryptResult);
	}

	/**
	 * DES解密
	 * @param data 待解密数据, 字节数组
	 * @param key 密钥, 字节数组
	 * @return 解密后数据字节数组
	 */
	public static byte[] desDecrypt(byte[] data, byte[] key) {
		// 还原二进制密钥为密钥对象
		Key k = generateDesKey(key);
		try {
			// 初始化, 设置为解密模式
			Cipher cipher = Cipher.getInstance(DES_ECB);
			cipher.init(Cipher.DECRYPT_MODE, k);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 使用AES解密字符串, 返回原始字符串.
	 * 
	 * @param input Hex编码的加密字符串
	 * @param key 符合AES要求的密钥
	 * @param iv 初始向量
	 */
	public static String aesDecrypt(byte[] input, byte[] key, byte[] iv) {
		byte[] decryptResult = aes(input, key, iv, Cipher.DECRYPT_MODE);
		return new String(decryptResult);
	}

	/**
	 * 使用AES加密或解密无编码的原始字节数组, 返回无编码的字节数组结果.
	 * 
	 * @param input 原始字节数组
	 * @param key 符合AES要求的密钥
	 * @param mode Cipher.ENCRYPT_MODE 或 Cipher.DECRYPT_MODE
	 */
	private static byte[] aes(byte[] input, byte[] key, int mode) {
		try {
			SecretKey secretKey = new SecretKeySpec(key, AES);
			Cipher cipher = Cipher.getInstance(AES);
			cipher.init(mode, secretKey);
			return cipher.doFinal(input);
		} catch (GeneralSecurityException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 使用AES加密或解密无编码的原始字节数组, 返回无编码的字节数组结果.
	 * 
	 * @param input 原始字节数组
	 * @param key 符合AES要求的密钥
	 * @param iv 初始向量
	 * @param mode Cipher.ENCRYPT_MODE 或 Cipher.DECRYPT_MODE
	 */
	private static byte[] aes(byte[] input, byte[] key, byte[] iv, int mode) {
		try {
			SecretKey secretKey = new SecretKeySpec(key, AES);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(AES_CBC);
			cipher.init(mode, secretKey, ivSpec);
			return cipher.doFinal(input);
		} catch (GeneralSecurityException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 生成AES密钥,返回字节数组, 默认长度为128位(16字节).
	 */
	public static byte[] generateAesKey() {
		return generateAesKey(DEFAULT_AES_KEYSIZE);
	}

	/**
	 * 生成Des密钥, 返回字节数组, 默认长度为56位
	 * @return
	 */
	public static byte[] generateDesKey() {
		return generateDesKey(DEFAULT_DES_KEYSIZE);
	}

	/**
	 * 生成AES密钥,可选长度为128,192,256位.
	 */
	public static byte[] generateAesKey(int keysize) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
			keyGenerator.init(keysize);
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey.getEncoded();
		} catch (GeneralSecurityException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 生成DES 密钥, 支持56位密钥, 64位密钥需要BC包支持:
	 * 56 KeyGenerator.getInstance(DES);
	 * 64 KeyGenerator.getInstance(DES, "BC");
	 * @param keysize 密钥长度
	 * @return
	 */
	public static byte[] generateDesKey(int keysize) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(DES);
			keyGenerator.init(keysize);
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * 将二进制DES密钥转化为密钥材料对象
	 * @param key 密钥对象
	 * @return 密钥对象
	 */
	public static Key generateDesKey(byte[] key)  {
		try {
			// 实例化密钥材料
			DESKeySpec desKeySpec = new DESKeySpec(key);
			// 实例化密钥工厂
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
			// 生成密钥
			return keyFactory.generateSecret(desKeySpec);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw Exceptions.unchecked(e);
		}
	}

	private static final String PBE_WITH_MD5_AND_DES = "PBEWITHMD5andDES";
	/**
	 * 根据用户提供的密码构建PBE密钥
	 * @param password
	 * @return
	 */
	public static SecretKey generatePBEKey(String password) {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		try {
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_WITH_MD5_AND_DES);
			return keyFactory.generateSecret(pbeKeySpec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * PBE加密
	 * @param data
	 * @param password
	 * @param salt
	 * @return
	 */
	public static byte[] pbeEncrypt(byte[] data, String password, byte[] salt) {
		SecretKey secretKey = generatePBEKey(password);
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 10);
		try {
			Cipher cipher = Cipher.getInstance(PBE_WITH_MD5_AND_DES);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchPaddingException e) {
			throw Exceptions.unchecked(e);
		}
	}

	/**
	 * PBE解密
	 * @param data
	 * @param password
	 * @param salt
	 * @return
	 */
	public static byte[] pbeDecrypt(byte[] data, String password, byte[] salt) {
		SecretKey secretKey = generatePBEKey(password);
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 10);
		try {
			Cipher cipher = Cipher.getInstance(PBE_WITH_MD5_AND_DES);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchPaddingException e) {
			throw Exceptions.unchecked(e);
		}
	}


	/**
	 * 随机盐
	 * @param len
	 * @return
	 */
	public static byte[] randomSalt(int len) {
		SecureRandom secureRandom = new SecureRandom();
		return random.generateSeed(len);
	}

	/**
	 * 生成随机向量,默认大小为cipher.getBlockSize(), 16字节.
	 */
	public static byte[] generateIV() {
		byte[] bytes = new byte[DEFAULT_IVSIZE];
		random.nextBytes(bytes);
		return bytes;
	}
}