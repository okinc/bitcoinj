package com.haoyouqian.bitcoinj.testor;

import org.junit.*;

import com.haoyouqian.bitcoinj.core.HYQKey;

public class HYQTestor {

	@Before
	public void setUp(){
		
	}
	
	@Test
	public void testHYQKey(){
		long timeStart = System.currentTimeMillis();
		
		//随机密钥对
		HYQKey rKey = new HYQKey();
		System.out.println("t1:" + (System.currentTimeMillis() - timeStart));
		System.out.println("privKey:" + rKey.getPrivateKeyAsHex());
		System.out.println("pubKey:" + rKey.getPublicKeyAsHex());
		System.out.println("Addr:" + rKey.getCommonAddress());
		System.out.println("t2:" + (System.currentTimeMillis() - timeStart));
		
		//由身份证生成密钥对
		String idNumber = "110102119801234567890";
		String salt = "1aead";
		String planKey = "0335ebbda8254cff61bcbe29c3cf7379f4bc8edc7ee0805960e39c17fa9dcfc87a";
		
		HYQKey hyqKey = HYQKey.fromIdNumber(idNumber, salt, planKey);
		System.out.println("t3:" + (System.currentTimeMillis() - timeStart));
		System.out.println("privKey:" + hyqKey.getPrivateKeyAsHex());
		System.out.println("pubKey:" + hyqKey.getPublicKeyAsHex());
		
		System.out.println("withdrawAddr:" + hyqKey.getCommonAddress());
		System.out.println("chargeAddr:"+hyqKey.getP2SHAddress());
		System.out.println("t4:" + (System.currentTimeMillis() - timeStart));
		
	}
}
