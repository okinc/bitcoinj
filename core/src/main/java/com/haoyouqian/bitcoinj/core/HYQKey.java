package com.haoyouqian.bitcoinj.core;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import com.haoyouqian.bitcoinj.params.HZMainNetParams;
import com.haoyouqian.bitcoinj.utils.OKUtils;

/**
 * HYQKey密钥对，（基于EC椭圆曲线）
 * @author chenzs
 *
 */
public class HYQKey extends ECKey {
	
	 public static final NetworkParameters netParam = HZMainNetParams.get();	//只用主网参数
	 public static final BigInteger PRIV_MIX_VALUE = BigInteger.ONE;
	 public static final BigInteger PRIV_MAX_VALUE = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140".getBytes());
	 
	 public byte[] planKey;		//保险计划公钥
	 
	/**
	 * 随机生成密钥对
	 */
	public HYQKey() {
		super();
	}
	
	
	private HYQKey(BigInteger privKey, @Nullable byte[] planKey) {
		super(privKey, null, true);
		this.planKey = planKey;
	}
	
	/**
	 * 以身份号码生成密钥对
	 * @param IdNumber		身份号码
	 * @param privacySalt	隐私保护盐
	 * @param hmacKey		hmac哈希密钥
	 * @return
	 */
	public static HYQKey fromIdNumber(String IdNumber, String privacySalt, String hmacKey) {
		
		if (IdNumber == null || privacySalt == null || hmacKey == null || 
				IdNumber == "" || privacySalt == "" || hmacKey == "") {
			throw new IllegalArgumentException("Illegal IdNumber or privacySalt or planKey input");
		}
	
		byte[] idWithSalt = (IdNumber + privacySalt).toLowerCase().getBytes(Charset.forName("UTF-8"));
		byte[] hmacSha256 = OKUtils.hmacSha256( hmacKey.getBytes(Charset.forName("UTF-8")), idWithSalt);
		
		BigInteger privKey = calculatePriv(hmacSha256);
		return new HYQKey(privKey, Utils.HEX.decode(hmacKey));
	}
	
	/**
	 * 普通地址（提现地址）
	 * @return
	 */
	public String  getCommonAddress() {
		return this.toAddress(netParam).toBase58();
	}
	
	/**
	 * p2sh地址（充值地址）
	 * @return
	 */
	public String getP2SHAddress() {
		if (planKey == null) {
			throw new IllegalArgumentException("Not a legal HYQKeypair(not has a planKey)");
		}
		
		List<ECKey> keyList = new ArrayList<ECKey>(2);
		keyList.add(this);
		keyList.add(ECKey.fromPublicOnly(planKey));
		Script p2shScript = ScriptBuilder.createP2SHOutputScript(1, keyList);
		return Address.fromP2SHScript(netParam, p2shScript).toBase58();
	}
	
	
	
	private static BigInteger calculatePriv(byte[] rootData) {
		byte[] sha256 = Sha256Hash.hash(rootData);
		BigInteger bigNumber = new BigInteger(sha256);
		if (bigNumber.compareTo(PRIV_MIX_VALUE) >= 1 && bigNumber.compareTo(PRIV_MAX_VALUE) <= -1) {
			return bigNumber;
		} else {
			return calculatePriv(sha256);
		}
	}
}
