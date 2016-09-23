package com.haoyouqian.bitcoinj.utils;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.crypto.KeyCrypterException;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;

public class OKUtils {

	static HMac createHmacSha256Digest(byte[] key) {
        SHA256Digest digest = new SHA256Digest();
        HMac hMac = new HMac(digest);
        hMac.init(new KeyParameter(key));
        return hMac;
    }

    static byte[] hmacSha256(HMac hmacSha256, byte[] input) {
    	hmacSha256.reset();
    	hmacSha256.update(input, 0, input.length);
        byte[] out = new byte[32];
        hmacSha256.doFinal(out, 0);
        return out;
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        return hmacSha256(createHmacSha256Digest(key), data);
    }
    
    
    public static byte[] signatures(Sha256Hash hash, ECKey key) throws KeyCrypterException{
    	if (key == null || !key.hasPrivKey()) {
    		throw new KeyCrypterException("no a valid private key");
    	}	
    	byte[] output = key.sign(hash).encodeToDER();
    	return output;
    }
    
    public static boolean verifySignatures(byte[] hash, byte[] sig, ECKey key) throws KeyCrypterException{
    	if (key == null) 
    		throw new KeyCrypterException("key invalid");
    	return key.verify(hash, sig);
    }
    
    public static boolean verifySignatures(byte[] hash, byte[] sig, byte[] pub) {
    	return ECKey.verify(hash, sig, pub);
    }
}
