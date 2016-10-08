package org.springside.modules.utils;

import org.junit.Before;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

/**
 * Created by lining on 16/6/30.
 */
public class RSACoderTest {

	private PrivateKey privateKey;
	private PublicKey publicKey;

	private void initKey(boolean isPrivate) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String keyPath = isPrivate ? "/id_rsa" : "/id_rsa.pub";
		InputStream stream = RSACoderTest.class.getResourceAsStream(keyPath);
		BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream));
		StringBuilder stringBuilder = new StringBuilder();

		String line;
		while ((line = bufferedReader.readLine()) != null) {
			if (line.charAt(0) == '-') {
				continue;
			}
			stringBuilder.append(line).append("\r");
		}

		BASE64Decoder base64Decoder = new BASE64Decoder();
		byte[] keyByte = base64Decoder.decodeBuffer(stringBuilder.toString());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		if (isPrivate) {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByte);
			privateKey = kf.generatePrivate(keySpec);
		} else {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByte);
			publicKey = kf.generatePublic(keySpec);
		}
		bufferedReader.close();

	}

	@Before
	public void setUp() throws Exception {
		initKey(true);
		initKey(false);

		System.out.println(Encodes.encodeBase64(privateKey.getEncoded()));
		System.out.println(Encodes.encodeBase64(publicKey.getEncoded()));
	}

	@Test
	public void testInitKey() throws NoSuchAlgorithmException {
		Map<String, RSAKey> keyMap = RSACoder.initKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(RSACoder.PUBLIC_KEY);
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(RSACoder.PRIVATE_KEY);

		System.out.println(Encodes.encodeBase64(publicKey.getEncoded()));
		System.out.println(Encodes.encodeBase64(privateKey.getEncoded()));
	}

	@Test
	public void decryptByPriKey() throws Exception {

	}

	@Test
	public void decryptByPubKey() throws Exception {

	}

	@Test
	public void encryptByPubKey() throws Exception {

	}

	@Test
	public void encryptByPriKey() throws Exception {

	}


}