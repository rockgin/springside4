/*******************************************************************************
 * Copyright (c) 2005, 2014 springside.github.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *******************************************************************************/
package org.springside.modules.utils;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class DigestsTest {

	private static final String SHA256 = "SHA-256";
	private static final String SHA512 = "SHA-512";

	@Test
	public void digestString() {
		String input = "user";
		byte[] shaResult = Digests.sha1(input.getBytes());
		System.out.println("sha1 in hex result                               :" + Encodes.encodeHex(shaResult));

		shaResult = Digests.sha2(input.getBytes(), SHA256);
		System.out.println("sha2 in hex result                               :" + Encodes.encodeHex(shaResult));


		byte[] salt = Digests.generateSalt(8);
		System.out.println("salt in hex                                      :" + Encodes.encodeHex(salt));

		shaResult = Digests.sha1(input.getBytes(), salt);
		System.out.println("sha1 in hex result with salt                     :" + Encodes.encodeHex(shaResult));

		shaResult = Digests.sha2(input.getBytes(), salt, SHA256);
		System.out.println("sha2 in hex result with salt                     :" + Encodes.encodeHex(shaResult));


		shaResult = Digests.sha1(input.getBytes(), salt, 1024);
		System.out.println("sha1 in hex result with salt and 1024 interations:" + Encodes.encodeHex(shaResult));

		shaResult = Digests.sha2(input.getBytes(), salt, 1024, SHA256);
		System.out.println("sha2 in hex result with salt and 1024 interations:" + Encodes.encodeHex(shaResult));

	}

	@Test
	public void testHmac() throws Exception {
		String msg = "hmac 测试";
		Digests.HmacAlgorithm algorithm = Digests.HmacAlgorithm.HMAC_MD5;

		byte[] hmacKey = Digests.HMAC.initHmacKey(algorithm);
		byte[] data00 = Digests.HMAC.hmacMD5(msg.getBytes(), hmacKey);
		byte[] data01 = Digests.HMAC.hmacMD5(msg.getBytes(), hmacKey);
		System.out.println(Encodes.encodeHex(data00));
		System.out.println(Encodes.encodeHex(data01));

		byte[] data10 = Digests.HMAC.hmacSHA1(msg.getBytes(), hmacKey);
		byte[] data11 = Digests.HMAC.hmacSHA1(msg.getBytes(), hmacKey);
		System.out.println(Encodes.encodeHex(data10));
		System.out.println(Encodes.encodeHex(data11));

		byte[] data20 = Digests.HMAC.hmacSHA2(msg.getBytes(), hmacKey, Digests.HmacAlgorithm.HMAC_SHA256);
		byte[] data21 = Digests.HMAC.hmacSHA2(msg.getBytes(), hmacKey, Digests.HmacAlgorithm.HMAC_SHA384);
		byte[] data22 = Digests.HMAC.hmacSHA2(msg.getBytes(), hmacKey, Digests.HmacAlgorithm.HMAC_SHA512);
		System.out.println(Encodes.encodeHex(data20));
		System.out.println(Encodes.encodeHex(data21));
		System.out.println(Encodes.encodeHex(data22));
	}

	@Test
	public void digestFile() throws IOException {

		InputStream is = this.getClass().getClassLoader().getResourceAsStream("test.txt");
		byte[] md5result = Digests.md5(is);
		byte[] sha1result = Digests.sha1(is);
		System.out.println("md5: " + Encodes.encodeHex(md5result));
		System.out.println("sha1:" + Encodes.encodeHex(sha1result));
	}

	@Test
	public void crc32String() {

		String input = "user1";
		int result = Digests.crc32(input);
		System.out.println("crc32 for user1:" + result);

		input = "user2";
		result = Digests.crc32(input);
		System.out.println("crc32 for user2:" + result);
	}

	@Test
	public void murmurString() {

		String input1 = "user1";
		int result = Digests.murmur32(input1);
		System.out.println("murmur32 for user1:" + result);

		String input2 = "user2";
		result = Digests.murmur32(input2);
		System.out.println("murmur32 for user2:" + result);

		int seed = (int) System.currentTimeMillis();
		result = Digests.murmur32(input1, seed);
		System.out.println("murmur32 with seed for user1:" + result);

		result = Digests.murmur32(input2, seed);
		System.out.println("murmur32 with seed for user2:" + result);

	}
}
