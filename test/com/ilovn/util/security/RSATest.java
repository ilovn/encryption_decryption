package com.ilovn.util.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

public class RSATest {
	private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcxnJtnqh/rMr+cSx2sIuMRJs5Rtp9Nj5GTSeMR7Zf/jRM8B0fWuiN3Iw0DxIVCLXaO/hhoc8OUtdN7nV90xmQVkJtvQ9TRBDep0QAuwuOa0IKVGzqIrvEbKoxpRlh6xEejtm0vcmrGyBNXb9vLzKijtC+D3MKw8/BP/WiRyo+CQIDAQAB";
	private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANzGcm2eqH+syv5xLHawi4xEmzlG2n02PkZNJ4xHtl/+NEzwHR9a6I3cjDQPEhUItdo7+GGhzw5S103udX3TGZBWQm29D1NEEN6nRAC7C45rQgpUbOoiu8RsqjGlGWHrER6O2bS9yasbIE1dv28vMqKO0L4PcwrDz8E/9aJHKj4JAgMBAAECgYBEy7oAmr4a+vdOjmmympUBoqdUE9Ylym9hbM10EyyrgQU/LFuG18c73Yv69O9Hiq1QUfu2QLvK1NmuuS33hX6jPURuSeK0wSjnXm7/9qqBST5NEcYAzR9T/LzTEy9VR2ez03wLRE5pVrrDSOf278b4owGtx/bNx6CrF4zcJn/SmQJBAPnvS/R9Rby37MeoamYWhtMFZH2OZdOi48CMqFT5kxZNGhVKIPBZ7/NVeudtQGn2u/js2EKClkOOOwJLuF8rXgsCQQDiIf+VKZlZ8rlFfd+Er7vokc9hjG1a2pZcbfdsuaNGBjCCfN1ufyEOBJxQH0pgeYuNkAzkBbfvxCKhjBU8qSS7AkEA5LFYn9MMv5zQFPT+voD4RxiVFen5NIjEu0g5Mt/W/b35EufsceDplY9u0Vn/abYx05jsXRdeZVw8lGIyxypIdwJBANAJ4T3UcI3M/WAORoWmuyRiiLzA2ZZdRTmxvZCcVLbGWPijcYAHm1xvJ3Oa5e1NxPKu1P0uuaLu+cFPw/Xz0qMCQQC3v8Di1DI5Sv8ZKSk6Iopctiw3Gq05DOq9mcFK8nLXK8Ze2S3LV+SwW5J5bwyYjIym/PgIWT8w8ZzbhhNT0PYk";

	@Before
	public void setUp() throws Exception {
		// Map<String, Object> keyMap = RSACoder.initKey();
		//
		// publicKey = RSACoder.getPublicKey(keyMap);
		// privateKey = RSACoder.getPrivateKey(keyMap);
		// System.err.println("公钥: \n\r" + publicKey);
		// System.err.println("私钥： \n\r" + privateKey);
	}

	@Test
	public void testPub2Pri() throws Exception {
		System.err.println("公钥加密——私钥解密");
		String inputStr = "abc";
		System.out.println("加密前:" + inputStr);

		String encodedData = RSA.encryptByPublicKey(inputStr, publicKey);

		System.out.println("加密后; " + encodedData);
		String decodedData = RSA.decryptByPrivateKey(encodedData, privateKey);
		System.err.println("解密后: " + decodedData);
		assertEquals(inputStr, decodedData);

	}

	@Test
	public void testPri2Pub() throws Exception {
		System.err.println("私钥加密——公钥解密");
		String inputStr = "sign";

		String encodedData = RSA.encryptByPrivateKey(inputStr, privateKey);

		String decodedData = RSA
				.decryptByPublicKey(encodedData, publicKey);

		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + decodedData);
		assertEquals(inputStr, decodedData); // 使用Junit断言，加密前的原文与解密后的明文是否一致。

		System.err.println("私钥签名——公钥验证签名");
		// 产生签名 这里的encodedData可以与下面的encodedData同时换成new int[]{2,45}
		String sign = RSA.sign(encodedData, privateKey); // 数字签名只要公钥人拿到签名的sign对比
		// ，自己公钥通过同样的byte[]运算得到签名是否一致。是到致代表这个公钥就是对的，就是为现在发私钥人服务的。
		System.err.println("签名:\r" + sign);

		// 验证签名
		boolean status = RSA.verify(encodedData, publicKey, sign);
		System.err.println("状态:\r" + status);
		assertTrue(status);

	}

}
