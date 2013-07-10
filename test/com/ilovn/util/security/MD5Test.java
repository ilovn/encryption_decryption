package com.ilovn.util.security;

import org.junit.Test;

import com.ilovn.util.security.MD5;

public class MD5Test {

	@Test
	public void test() {
		System.out.println(MD5.encrypt("123456"));
	}

}
