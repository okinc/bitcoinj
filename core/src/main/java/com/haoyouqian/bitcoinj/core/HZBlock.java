package com.haoyouqian.bitcoinj.core;

import static org.bitcoinj.core.Coin.FIFTY_COINS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import javax.annotation.Nullable;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.BlockInf;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.MessageSerializer;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VarInt;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;

public class HZBlock extends Message implements BlockInf{
    /**
     * Flags used to control which elements of block validation are done on
     * received blocks.
     */
    public enum VerifyFlag {
        /** Check that block height is in coinbase transaction (BIP 34). */
        HEIGHT_IN_COINBASE
    }

    private static final Logger log = LoggerFactory.getLogger(HZBlock.class);

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
//    public static final int HEADER_SIZE = 80;
    /** OKBlockHeader大小为137Bytes. */
    public static final int HEADER_SIZE = 137;

    static final long ALLOWED_TIME_DRIFT = 48 * 60 * 60; // Same value as Bitcoin Core.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1024 * 1000 * 1000;	//1024M
    
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /** A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing. */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    
    //OKToken OKBlock从version=1起就支持以下BIP协议
    public static final int BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final int BLOCK_VERSION_BIP34 = 1;					//bitcoin is 2
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final int BLOCK_VERSION_BIP66 = 1;					//bitcoin is 3
    /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY */
    public static final int BLOCK_VERSION_BIP65 = 1;					//bitcoin is 4

    // Fields defined as part of the protocol format.
    /*sizeof(BlockHeader)=137,每个区块头大小固定为137字节。
    class  BlockHeader{
    	 int32 nVersion;			//版本号
    	 Compress264Key	planKey;		//计划公钥 byte[33]
    	 uint256 hashPrevBlock;	//前导块哈希值
    	 uint256 hashMerleRoot;	//交易数据Merleroot值
    	 uint256 hashPreAnchor;	//前导块锚定交易哈希值
    	 uint32  nTime;			//块产生时间
    	}
    */
    private int version;
    private Compress264Key planKey;	
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot;
    private Sha256Hash prevAnchorHash;	//上个区块锚定交易hash
    private long time;
    
    //当前block锚定hash，不参与hash计算
    private Sha256Hash anchorHash;	
    private byte[] signatures;

//    private long difficultyTarget; // "nBits"
//    private long nonce;

    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers. */
//    @Nullable List<HZTransaction> transactions;
    /** 仅包含交易的hash列表 */
    @Nullable List<Sha256Hash> txHashs;	

    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private Sha256Hash hash;

    protected boolean headerBytesValid;
    protected boolean transactionBytesValid;
    
    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    protected int optimalEncodingMessageSize;

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests. */
    HZBlock(NetworkParameters params, int setVersion) {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        version = setVersion;
//        difficultyTarget = 0x1d07fff8L;
        time =(int) (System.currentTimeMillis() / 1000);
        prevBlockHash = Sha256Hash.ZERO_HASH;

        length = HEADER_SIZE;
    }

    /**
     * Constructs a block object from the Bitcoin wire format.
     */
    public HZBlock(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0, params.getDefaultSerializer(), payloadBytes.length);
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public HZBlock(NetworkParameters params, byte[] payloadBytes, MessageSerializer serializer, int length)
            throws ProtocolException {
        super(params, payloadBytes, 0, serializer, length);
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public HZBlock(NetworkParameters params, byte[] payloadBytes, int offset, MessageSerializer serializer, int length)
            throws ProtocolException {
        super(params, payloadBytes, offset, serializer, length);
    }

    /**
     * Construct a block object from the Bitcoin wire format. Used in the case of a block
     * contained within another message (i.e. for AuxPoW header).
     *
     * @param params NetworkParameters object.
     * @param payloadBytes Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parent The message element which contains this block, maybe null for no parent.
     * @param serializer the serializer to use for this block.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public HZBlock(NetworkParameters params, byte[] payloadBytes, int offset, @Nullable Message parent, MessageSerializer serializer, int length)
            throws ProtocolException {
        // TODO: Keep the parent
        super(params, payloadBytes, offset, serializer, length);
    }

    /**
	 * 构建HZBlock
	 * @param params	网络参数
	 * @param version	版本
	 * @param prevBlockHash	上个区块hash	
	 * @param merkleRoot	交易merkleroot ，可以为null， 自动通过transactions计算
	 * @param prevAnchorHash	上个区块锚定交易hash
	 * @param time				时间（单位：秒）
	 * @param transactions		交易列表
	 */
	public HZBlock(NetworkParameters params, int version, Compress264Key planKey, Sha256Hash prevBlockHash, 
			@Nullable Sha256Hash merkleRoot, Sha256Hash prevAnchorHash, int time, List<Sha256Hash> txHashs) {
        super(params);
        this.version = version;
        this.planKey = planKey == null ? Compress264Key.ZERO_KEY : planKey;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.prevAnchorHash = prevAnchorHash == null ? Sha256Hash.ZERO_HASH : prevAnchorHash;
        this.time = time;
        this.txHashs = new LinkedList<Sha256Hash>();
        if(txHashs != null)
        	this.txHashs.addAll(txHashs);
    }
    
	/**
	 * 构建OKBlock
	 * @param params
	 * @param version
	 * @param prevBlockHash
	 * @param prevAnchorHash
	 * @param transactions
	 */
	public HZBlock(NetworkParameters params, int version, Compress264Key planKey, Sha256Hash prevBlockHash,
			Sha256Hash prevAnchorHash, @Nullable List<Sha256Hash> txHashs) {
		this(params, version, planKey, prevBlockHash, null, prevAnchorHash, (int)(System.currentTimeMillis()/1000), txHashs);
		
	}


//    /**
//     * <p>A utility method that calculates how much new Bitcoin would be created by the block at the given height.
//     * The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks). At the dawn of
//     * the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on. The size of
//     * a coinbase transaction is inflation plus fees.</p>
//     *
//     * <p>The half-life is controlled by {@link org.bitcoinj.core.NetworkParameters#getSubsidyDecreaseBlockCount()}.
//     * </p>
//     */
//    public Coin getBlockInflation(int height) {
//        return FIFTY_COINS.shiftRight(height / params.getSubsidyDecreaseBlockCount());
//    }

    /**
     * Parse transactions from the block.
     * 
     * @param transactionsOffset Offset of the transactions within the block.
     * Useful for non-Bitcoin chains where the block header may not be a fixed
     * size.
     */
    protected void parseTransactions(final int transactionsOffset) throws ProtocolException {
        cursor = transactionsOffset;
        optimalEncodingMessageSize = HEADER_SIZE;
        if (payload.length == cursor) {
            // This message is just a header, it has no transactions.
            transactionBytesValid = false;
            return;
        }

        int numTransactions = (int) readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numTransactions);
        txHashs = new ArrayList<Sha256Hash>(numTransactions);
        for (int i = 0; i < numTransactions; i++) {
        	Sha256Hash hash = readHash();
            txHashs.add(hash);
            cursor += Sha256Hash.LENGTH;
            optimalEncodingMessageSize += Sha256Hash.LENGTH;
        }
        transactionBytesValid = serializer.isParseRetainMode();
    }
    
    protected void parseSignatures(final int sigOffset) throws ProtocolException {
    	cursor = sigOffset;
    	if (payload.length == cursor) {
    		this.signatures = null;
    		return;
    	}
    	int sigLenght = (int)readVarInt();
    	optimalEncodingMessageSize += VarInt.sizeOf(sigLenght);
    	this.signatures = Utils.reverseBytes(readBytes(sigLenght));
    	cursor += sigLenght;
    	optimalEncodingMessageSize += sigLenght;
    }

    @Override
    protected void parse() throws ProtocolException {
        // header
        cursor = offset;
        version = (int)readUint32();
        planKey = readCompressKey();
        prevBlockHash = readHash();
        merkleRoot = readHash();
        prevAnchorHash = readHash();
        time = (int)readUint32();
        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, cursor - offset));
        headerBytesValid = serializer.isParseRetainMode();

        // transactions
        parseTransactions(offset + HEADER_SIZE);
        //signatures 签名
        parseSignatures(cursor);
        length = cursor - offset;
    }
    
    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = bitcoinSerialize().length;
        return optimalEncodingMessageSize;
    }

    // default for testing
    void writeHeader(OutputStream stream) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null && payload.length >= offset + HEADER_SIZE) {
            stream.write(payload, offset, HEADER_SIZE);
            return;
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(planKey.getReversedBytes());
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot().getReversedBytes());
        stream.write(prevAnchorHash.getReversedBytes());
        Utils.uint32ToByteStreamLE(time, stream);
    }

    private void writeTransactionsHash(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (txHashs == null) {
            return;
        }

        // confirmed we must have transactions either cached or as objects.
        if (transactionBytesValid && payload != null && payload.length >= offset + length) {
            stream.write(payload, offset + HEADER_SIZE, length - HEADER_SIZE);
            return;
        }

        if (txHashs != null) {
            stream.write(new VarInt(txHashs.size()).encode());
            for (Sha256Hash txid : txHashs) {
               stream.write(txid.getReversedBytes());
            }
        }
    }
    
    //写签名
    private void writeSignatures(OutputStream stream) throws IOException {
    	if (this.signatures == null) {
    		return;
    	}
    	
    	stream.write(new VarInt(signatures.length).encode());
    	stream.write(Utils.reverseBytes(this.signatures));
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws IOException
     */
    @Override
    public byte[] bitcoinSerialize() {
        // we have completely cached byte array.
        if (headerBytesValid && transactionBytesValid) {
            Preconditions.checkNotNull(payload, "Bytes should never be null if headerBytesValid && transactionBytesValid");
            if (length == payload.length) {
                return payload;
            } else {
                // byte array is offset so copy out the correct range.
                byte[] buf = new byte[length];
                System.arraycopy(payload, offset, buf, 0, length);
                return buf;
            }
        }

        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE + guessTransactionsLength() : length);
        try {
            writeHeader(stream);
            writeTransactionsHash(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        // We may only have enough data to write the header.
        writeTransactionsHash(stream);
    }

    /**
     * Provides a reasonable guess at the byte length of the transactions part of the block.
     * The returned value will be accurate in 99% of cases and in those cases where not will probably slightly
     * oversize.
     *
     * This is used to preallocate the underlying byte array for a ByteArrayOutputStream.  If the size is under the
     * real value the only penalty is resizing of the underlying byte array.
     */
    private int guessTransactionsLength() {
        if (transactionBytesValid)
            return payload.length - HEADER_SIZE;
        if (txHashs == null)
            return 0;
        int len = VarInt.sizeOf(txHashs.size());
        len += (txHashs.size() * Sha256Hash.LENGTH);
       
        return len;
    }

    @Override
    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        headerBytesValid = false;
        if (!transactionBytesValid)
            payload = null;
        hash = null;
    }

    private void unCacheTransactions() {
        transactionBytesValid = false;
        if (!headerBytesValid)
            payload = null;
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null)
            hash = calculateHash();
        return hash;
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Returns the work represented by this block.<p>
     *
     * Work is defined as the number of tries needed to solve a block in the
     * average case. Consider a difficulty target that covers 5% of all possible
     * hash values. Then the work of the block will be 20. As the target gets
     * lower, the amount of work goes up.
     */
//    public BigInteger getWork() throws VerificationException {
//        BigInteger target = getDifficultyTargetAsInteger();
//        return LARGEST_HASH.divide(target.add(BigInteger.ONE));
//    }

    /** Returns a copy of the block, but without any transactions. */
    public HZBlock cloneAsHeader() {
    	HZBlock block = new HZBlock(params, BLOCK_VERSION_GENESIS);
        copyBitcoinHeaderTo(block);
        return block;
    }

    /** Copy the block without transactions into the provided empty block. */
    protected final void copyBitcoinHeaderTo(final HZBlock block) {
        block.prevBlockHash = prevBlockHash;
        block.merkleRoot = getMerkleRoot();
        block.prevAnchorHash = prevAnchorHash;
        block.version = version;
        block.planKey = planKey;
        block.time = time;
        block.txHashs = null;
        block.hash = getHash();
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(" block: \n");
        s.append("   hash: ").append(getHashAsString()).append('\n');
        s.append("   version: ").append(version);
        String bips = Joiner.on(", ").skipNulls().join(isBIP34() ? "BIP34" : null, isBIP66() ? "BIP66" : null,
                isBIP65() ? "BIP65" : null);
        if (!bips.isEmpty())
            s.append(" (").append(bips).append(')');
        s.append('\n');
        s.append("   planKey:").append(getPlanKey()).append("\n");
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n");
        s.append("   merkle root: ").append(getMerkleRoot()).append("\n");
        s.append("   previous anchor: ").append(getPrevAnchorHash()).append("\n");
        s.append("   current anchor:[ ").append(getAnchorHash()).append(" ](not wraped by hash)\n");
        s.append("   time: ").append(time).append(" (").append(Utils.dateTimeFormat((long)time * 1000L)).append(")\n");
       
        if (txHashs != null && txHashs.size() > 0) {
            s.append("   with ").append(txHashs.size()).append(" transaction(s):\n");
            for (Sha256Hash txid : txHashs) {
                s.append(txid.toString());
            }
        }
        return s.toString();
    }

    /**
     * <p>Finds a value of nonce that makes the blocks hash lower than the difficulty target. This is called mining, but
     * solve() is far too slow to do real mining with. It exists only for unit testing purposes.
     *
     * <p>This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change
     * extraNonce.</p>
     */
//    public void solve() {
//        while (true) {
//            try {
//                // Is our proof of work valid yet?
//                if (checkProofOfWork(false))
//                    return;
//                // No, so increment the nonce and try again.
//                setNonce(getNonce() + 1);
//            } catch (VerificationException e) {
//                throw new RuntimeException(e); // Cannot happen.
//            }
//        }
//    }

//    /**
//     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
//     * target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception
//     * is thrown.
//     */
//    public BigInteger getDifficultyTargetAsInteger() throws VerificationException {
//    	
//       BigInteger target = Utils.decodeCompactBits(difficultyTarget);
//        if (target.signum() <= 0 || target.compareTo(params.maxTarget) > 0)
//            throw new VerificationException("Difficulty target is bad: " + target.toString());
//        return target;
//    }

//    /** Returns true if the hash of the block is OK (lower than difficulty target). */
//    protected boolean checkProofOfWork(boolean throwException) throws VerificationException {
//        // This part is key - it is what proves the block was as difficult to make as it claims
//        // to be. Note however that in the context of this function, the block can claim to be
//        // as difficult as it wants to be .... if somebody was able to take control of our network
//        // connection and fork us onto a different chain, they could send us valid blocks with
//        // ridiculously easy difficulty and this function would accept them.
//        //
//        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
//        // field is of the right value. This requires us to have the preceeding blocks.
//
//    	
//        BigInteger target = getDifficultyTargetAsInteger();
//
//        BigInteger h = getHash().toBigInteger();
//        if (h.compareTo(target) > 0) {
//            // Proof of work check failed!
//            if (throwException)
//                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs "
//                        + target.toString(16));
//            else
//                return false;
//        }
//    	
//        return true;
//    }

    private void checkTimestamp() throws VerificationException {
        // Allow injection of a fake clock to allow unit testing.
        long currentTime = Utils.currentTimeSeconds();
        if (time > currentTime + ALLOWED_TIME_DRIFT)
            throw new VerificationException(String.format(Locale.US, "Block too far in future: %d vs %d", time, currentTime + ALLOWED_TIME_DRIFT));
    }

    private void checkSigOps() throws VerificationException {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
       
    }

    private void checkMerkleRoot() throws VerificationException {
        Sha256Hash calculatedRoot = calculateMerkleRoot();
        if (!calculatedRoot.equals(merkleRoot)) {
            log.error("Merkle tree did not verify");
            throw new VerificationException("Merkle hashes do not match: " + calculatedRoot + " vs " + merkleRoot);
        }
    }

    private Sha256Hash calculateMerkleRoot() {
        List<byte[]> tree = buildMerkleTree();
        return Sha256Hash.wrap(tree.get(tree.size() - 1));
    }

    private List<byte[]> buildMerkleTree() {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        ArrayList<byte[]> tree = new ArrayList<byte[]>();
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Sha256Hash txhash : txHashs) {
            tree.add(txhash.getBytes());
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = txHashs.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                byte[] leftBytes = Utils.reverseBytes(tree.get(levelOffset + left));
                byte[] rightBytes = Utils.reverseBytes(tree.get(levelOffset + right));
                tree.add(Utils.reverseBytes(Sha256Hash.hashTwice(leftBytes, 0, 32, rightBytes, 0, 32)));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }

    /**
     * Verify the transactions on a block.
     *
     * @param height block height, if known, or -1 otherwise. If provided, used
     * to validate the coinbase input script of v2 and above blocks.
     * @throws VerificationException if there was an error verifying the block.
     */
    private void checkTransactions(final int height, final EnumSet<VerifyFlag> flags)
            throws VerificationException {
        
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws VerificationException
     */
    public void verifyHeader() throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
//        checkProofOfWork(true);
        checkTimestamp();
    }

    /**
     * Checks the block contents
     *
     * @param height block height, if known, or -1 otherwise. If valid, used
     * to validate the coinbase input script of v2 and above blocks.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verifyTransactions(final int height, final EnumSet<VerifyFlag> flags) throws VerificationException {
        
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     *
     * @param height block height, if known, or -1 otherwise.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verify(final int height, final EnumSet<VerifyFlag> flags) throws VerificationException {
        verifyHeader();
        verifyTransactions(height, flags);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getHash().equals(((HZBlock)o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot() {
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader();
            merkleRoot = calculateMerkleRoot();
        }
        return merkleRoot;
    }

    /** Exists only for unit testing. */
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        hash = null;
    }

    /** Adds a transaction to this block. The nonce and merkle root are invalid after this. */
    public void addTransaction(HZTransaction t) {
        addTransaction(t, true);
    }

    /** Adds a transaction to this block, with or without checking the sanity of doing so */
    void addTransaction(HZTransaction t, boolean runSanityChecks) {
        unCacheTransactions();
        if (txHashs == null) {
        	txHashs = new LinkedList<Sha256Hash>();
        }
        t.setParent(this);
       
        txHashs.add(t.getHash());
        adjustLength(txHashs.size(), 32);
        // Force a recalculation next time the values are needed.
        merkleRoot = null;
        hash = null;
    }

    /** Returns the version of the block data structure as defined by the Bitcoin protocol. */
    public int getVersion() {
        return version;
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }
    
    public List<Sha256Hash> getTxList() {
    	return this.txHashs;
    }
    
    public void setTxList(List<Sha256Hash> txHashs) {
    	unCacheHeader();
    	this.txHashs = txHashs;
    	this.merkleRoot = null;
    	this.hash = null;
    	this.adjustLength(0, UNKNOWN_LENGTH);
    }
    

    void setPrevBlockHash(Sha256Hash prevBlockHash) {
        unCacheHeader();
        this.prevBlockHash = prevBlockHash;
        this.hash = null;
    }
    
    /**
     * 上个区块锚定交易hash
     * @return
     */
    public Sha256Hash getPrevAnchorHash(){
    	return prevAnchorHash;
    }
    
    void setPrevAnchorHash(Sha256Hash prevAnchorHash){
    	unCacheHeader();
    	this.prevAnchorHash = prevAnchorHash == null ? Sha256Hash.ZERO_HASH :prevAnchorHash;
    	this.hash = null;
    }
    
    public Compress264Key getPlanKey() {
    	return this.planKey;
    }
    
    public void setPlanKey(Compress264Key planKey) {
    	unCacheHeader();
    	this.planKey = planKey;
    	this.hash = null;
    }
    
	/**
	 * 当前Block锚定交易Hash，区别于preAnchorHash,不参与Hash计算
	 */
	public void setAnchorHash(Sha256Hash anchorHash) {
		this.anchorHash = anchorHash;
	}
	
	/**
	 * 当前Block锚定交易Hash，区别于preAnchorHash, 不参与Hash计算
	 */
	public Sha256Hash getAnchorHash() {
		return anchorHash;
	}
	
	public void setSignatures(byte[] sig) {
		this.signatures = sig;
	}

	public byte[] getSignatures() {
		return signatures;
	}
	

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     */
    public long getTimeSeconds() {
        return time;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    public Date getTime() {
        return new Date((long)getTimeSeconds()*1000L);
    }

    public void setTime(long time) {
        unCacheHeader();
        this.time = time;
        this.hash = null;
    }

    /**
     * Returns the difficulty of the proof of work that this block should meet encoded <b>in compact form</b>. The {@link
     * BlockChain} verifies that this is not too easy by looking at the length of the chain when the block is added.
     * To find the actual value the hash should be compared against, use
     * {@link org.bitcoinj.core.Block#getDifficultyTargetAsInteger()}. Note that this is <b>not</b> the same as
     * the difficulty value reported by the Bitcoin "getdifficulty" RPC that you may see on various block explorers.
     * That number is the result of applying a formula to the underlying difficulty to normalize the minimum to 1.
     * Calculating the difficulty that way is currently unsupported.
     */
    public long getDifficultyTarget() {
    	return 0;
    }

    /** Sets the difficulty target in compact form. */
    public void setDifficultyTarget(long compactForm) {

    }

    /**
     * Returns the nonce, an arbitrary value that exists only to make the hash of the block header fall below the
     * difficulty target.
     */
    public long getNonce() {
//        return nonce;
    	return 0;
    }

    /** Sets the nonce and clears any cached data. */
    public void setNonce(long nonce) {
//        unCacheHeader();
//        this.nonce = nonce;
//        this.hash = null;
    }

    /** Returns an immutable list of transactions held in this block, or null if this object represents just a header. */
    @Nullable
    public List<Sha256Hash> getTransactionsHash() {
        return txHashs == null ? null : ImmutableList.copyOf(txHashs);
    }

    // ///////////////////////////////////////////////////////////////////////////////////////////////
    // Unit testing related methods.

    // Used to make transactions unique.
    private static int txCounter;

    /** Adds a coinbase transaction to the block. This exists for unit tests.
     * 
     * @param height block height, if known, or -1 otherwise.
     */
  
    static final byte[] EMPTY_BYTES = new byte[32];

    // It's pretty weak to have this around at runtime: fix later.
    private static final byte[] pubkeyForTesting = new ECKey().getPubKey();

   

    /**
     * Return whether this block contains any transactions.
     * 
     * @return  true if the block contains transactions, false otherwise (is
     * purely a header).
     */
    public boolean hasTransactions() {
        return !this.txHashs.isEmpty();
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki">BIP34: Height in Coinbase</a>.
     */
    public boolean isBIP34() {
        return version >= BLOCK_VERSION_BIP34;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki">BIP66: Strict DER signatures</a>.
     */
    public boolean isBIP66() {
        return version >= BLOCK_VERSION_BIP66;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki">BIP65: OP_CHECKLOCKTIMEVERIFY</a>.
     */
    public boolean isBIP65() {
        return version >= BLOCK_VERSION_BIP65;
    }



	
	
	private Compress264Key readCompressKey() {
		return Compress264Key.wrapReversed(readBytes(Compress264Key.LENGTH));
	}

	@Override
	public void solve() {
		// TODO Auto-generated method stub
		
	}
	
	public void sign(byte[] privateKey) {
		
	}
}

