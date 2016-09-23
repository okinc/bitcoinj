package com.haoyouqian.bitcoinj.params;

import org.bitcoinj.core.Context;
import org.bitcoinj.core.Utils;

import com.oklink.bitcoinj.params.OKAbstractNetParams;

public class HZMainNetParams extends OKAbstractNetParams {

	 public static final String BITCOIN_SCHEME = "bafanghuzhu";
	 public static final byte[]  ANACHOR_FIX_FLAG = {'8', 'h','z'};	//锚定OP_RETURE中的前缀 (8hz)
	 
	 private static final long serialVersionUID = 1L;

		public HZMainNetParams(){
			super();
			
			interval = INTERVAL;
			targetTimespan = TARGET_TIMESPAN;
			maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
			dumpedPrivateKeyHeader = 128;

			bip32HeaderPub = 0x0488B21E; // The 4 byte header that serializes in base58 to "xpub".
			bip32HeaderPriv = 0x0488ADE4; //The 4 byte header that serializes in base58 to "xprv"
		        
			addressHeader = 40;	//H 充值地址
			p2shHeader = 80;	//Z 提现地址
			
			port = 6969;
			packetMagic = 0x6266687a; //bfhz
			//接受地址版本号！
			acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
			
			new Context(this);
		}
		
		
		 private static HZMainNetParams instance;
		 
		 public static synchronized HZMainNetParams get() {
	        if (instance == null) {
	            instance = new HZMainNetParams();
	        }
	        return instance;
	    }

		@Override
		public String getPaymentProtocolId() {
			return PAYMENT_PROTOCOL_ID_MAINNET;
		}
}
