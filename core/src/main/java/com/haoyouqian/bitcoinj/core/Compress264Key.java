package com.haoyouqian.bitcoinj.core;

import static com.google.common.base.Preconditions.checkArgument;

import java.io.Serializable;
import java.util.Arrays;

import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;

//压缩公钥（33byte*8=264）
@SuppressWarnings("serial")
public class Compress264Key implements Serializable {
	public static final int LENGTH = 33; // bytes
	public static final Compress264Key ZERO_KEY = wrap(new byte[LENGTH]);
	
	private final byte[] bytes;

	
	public Compress264Key(byte[] rawBytes) {
	    checkArgument(rawBytes.length == LENGTH);
	    this.bytes = rawBytes;
	}
	
	public static Compress264Key wrap(byte[] rawBytes) {
        return new Compress264Key(rawBytes);
    }
	
	public static Compress264Key wrap(String hexString) {
	    return wrap(Utils.HEX.decode(hexString));
	}
	
	public static Compress264Key wrapReversed(byte[] rawBytes) {
        return wrap(Utils.reverseBytes(rawBytes));
    }
	
	/**
     * Returns a reversed copy of the internal byte array.
     */
    public byte[] getReversedBytes() {
        return Utils.reverseBytes(bytes);
    }

	@Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(bytes, ((Compress264Key)o).bytes);
    }

	
	@Override
    public String toString() {
        return Utils.HEX.encode(bytes);
    }
	
	
	
}
