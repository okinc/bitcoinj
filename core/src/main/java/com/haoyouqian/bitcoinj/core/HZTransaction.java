package com.haoyouqian.bitcoinj.core;

import static org.bitcoinj.core.Utils.uint32ToByteStreamLE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;

import javax.annotation.Nullable;

import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.MessageSerializer;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VarInt;
import org.bitcoinj.script.Script;


public class HZTransaction extends Transaction {
	
	protected long	type;			//交易类型
	protected long	createTime;		//创建时间
	protected long  nonce;			//随机数
	

	public HZTransaction(NetworkParameters params, byte[] payload, int offset, Message parent,
			MessageSerializer setSerializer, int length) throws ProtocolException {
		super(params, payload, offset, parent, setSerializer, length);
	}

	public HZTransaction(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
		super(params, payload, offset);
	}

	public HZTransaction(NetworkParameters params, byte[] payload, Message parent, MessageSerializer setSerializer,
			int length) throws ProtocolException {
		super(params, payload, parent, setSerializer, length);
	}

	public HZTransaction(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
		super(params, payloadBytes);
	}
	
	public HZTransaction(NetworkParameters params, int type) {
		super(params);
		this.type = type;
		this.createTime = (int) (System.currentTimeMillis() / 1000);
		this.nonce = (long)(Math.random() * System.currentTimeMillis()) ;
	}
	
	public long getType() {
		return type;
	}

	public void setType(long type) {
		unCache();
		this.type = type;
	}

	public long getCreateTime() {
		return createTime;
	}

	public void setCreateTime(long createTime) {
		unCache();
		this.createTime = createTime;
	}

	
	@Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
		uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerialize(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerialize(stream);
        
        uint32ToByteStreamLE(lockTime, stream);
        
		uint32ToByteStreamLE(type, stream);			//交易列行
		uint32ToByteStreamLE(createTime, stream);	//创建时间
		uint32ToByteStreamLE(nonce, stream);
    }
	
	@Override
	public byte[] bitcoinSerialize() {
		 // 1st attempt to use a cached array.
        if (payload != null) {
            if (offset == 0 && length == payload.length) {
                // Cached byte array is the entire message with no extras so we can return as is and avoid an array
                // copy.
                return payload;
            }

            byte[] buf = new byte[length];
            System.arraycopy(payload, offset, buf, 0, length);
            return buf;
        }
        
		int len = 16 + VarInt.sizeOf(inputs.size()) + VarInt.sizeOf(outputs.size());
		len += (length == UNKNOWN_LENGTH ? 255 : length);
		ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(len);
		try {
			bitcoinSerializeToStream(stream);
		} catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
		
		if (serializer.isParseRetainMode()) {
			 payload = stream.toByteArray();
	         cursor = cursor - offset;
	         offset = 0;
	         recached = true;
	         length = payload.length;
	         return payload;
		}
		
		byte[] buf = stream.toByteArray();
	    length = buf.length;
	    return buf;
	}

	@Override
	protected void parse() throws ProtocolException {
		 cursor = offset;

        version = readUint32();
        optimalEncodingMessageSize = 4;

        // First come the inputs.
        long numInputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numInputs);
        inputs = new ArrayList<TransactionInput>((int) numInputs);
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(params, this, payload, cursor, serializer);
            inputs.add(input);
            long scriptLen = readVarInt(TransactionOutPoint.MESSAGE_LENGTH);
            optimalEncodingMessageSize += TransactionOutPoint.MESSAGE_LENGTH + VarInt.sizeOf(scriptLen) + scriptLen + 4;
            cursor += scriptLen + 4;
        }
        // Now the outputs
        long numOutputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numOutputs);
        outputs = new ArrayList<TransactionOutput>((int) numOutputs);
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(params, this, payload, cursor, serializer);
            outputs.add(output);
            long scriptLen = readVarInt(8);
            optimalEncodingMessageSize += 8 + VarInt.sizeOf(scriptLen) + scriptLen;
            cursor += scriptLen;
        }
        lockTime = readUint32();
        type = readUint32();
        createTime = readUint32();
        nonce = readUint32();
        optimalEncodingMessageSize += 16;
        length = cursor - offset;
	}
	
	 public String toString(@Nullable AbstractBlockChain chain) {
	        StringBuilder s = new StringBuilder();
	        s.append("  ").append(getHashAsString()).append('\n');
	        if (hasConfidence())
	            s.append("  confidence: ").append(getConfidence()).append('\n');
	        if (isTimeLocked()) {
	            s.append("  time locked until ");
	            if (lockTime < LOCKTIME_THRESHOLD) {
	                s.append("block ").append(lockTime);
	                if (chain != null) {
	                    s.append(" (estimated to be reached at ")
	                            .append(Utils.dateTimeFormat(chain.estimateBlockTime((int) lockTime))).append(')');
	                }
	            } else {
	                s.append(Utils.dateTimeFormat(lockTime * 1000));
	            }
	            s.append('\n');
	        }
	        if (isOptInFullRBF()) {
	            s.append("  opts into full replace-by-fee\n");
	        }
	        if (inputs.size() == 0) {
	            s.append("  INCOMPLETE: No inputs!\n");
	            return s.toString();
	        }
	        if (isCoinBase()) {
	            String script;
	            String script2;
	            try {
	                script = inputs.get(0).getScriptSig().toString();
	                script2 = outputs.get(0).getScriptPubKey().toString();
	            } catch (ScriptException e) {
	                script = "???";
	                script2 = "???";
	            }
	            s.append("     == COINBASE TXN (scriptSig ").append(script)
	                .append(")  (scriptPubKey ").append(script2).append(")\n");
//	            return s.toString();
	        }
	        for (TransactionInput in : inputs) {
	            s.append("     ");
	            s.append("in   ");

	            try {
	                Script scriptSig = in.getScriptSig();
	                s.append(scriptSig);
	                if (in.getValue() != null)
	                    s.append(" ").append(in.getValue().toFriendlyString());
	                s.append("\n          ");
	                s.append("outpoint:");
	                final TransactionOutPoint outpoint = in.getOutpoint();
	                s.append(outpoint.toString());
	                final TransactionOutput connectedOutput = outpoint.getConnectedOutput();
	                if (connectedOutput != null) {
	                    Script scriptPubKey = connectedOutput.getScriptPubKey();
	                    if (scriptPubKey.isSentToAddress() || scriptPubKey.isPayToScriptHash()) {
	                        s.append(" hash160:");
	                        s.append(Utils.HEX.encode(scriptPubKey.getPubKeyHash()));
	                    }
	                }
	                if (in.hasSequence()) {
	                    s.append("\n          sequence:").append(Long.toHexString(in.getSequenceNumber()));
	                    if (in.isOptInFullRBF())
	                        s.append(", opts into full RBF");
	                }
	            } catch (Exception e) {
	                s.append("[exception: ").append(e.getMessage()).append("]");
	            }
	            s.append('\n');
	        }
	        for (TransactionOutput out : outputs) {
	            s.append("     ");
	            s.append("out  ");
	            try {
	                Script scriptPubKey = out.getScriptPubKey();
	                s.append(scriptPubKey);
	                s.append(" ");
	                s.append(out.getValue());
	                if (!out.isAvailableForSpending()) {
	                    s.append(" Spent");
	                }
	                if (out.getSpentBy() != null) {
	                    s.append(" by ");
	                    s.append(out.getSpentBy().getParentTransaction().getHashAsString());
	                }
	            } catch (Exception e) {
	                s.append("[exception: ").append(e.getMessage()).append("]");
	            }
	            s.append('\n');
	        }
	        
	         
	        s.append("     type ").append(type).append('\n');
	        s.append("     createtime ").append(Utils.dateTimeFormat(createTime * 1000)).append('\n');
	        s.append("    nonce ").append(nonce).append('\n');
	        return s.toString();
	    }
	
	
}
