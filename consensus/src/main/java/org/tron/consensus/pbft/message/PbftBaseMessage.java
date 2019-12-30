package org.tron.consensus.pbft.message;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.spongycastle.util.encoders.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.overlay.message.Message;
import org.tron.common.utils.Sha256Hash;
import org.tron.common.utils.WalletUtil;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.exception.P2pException;
import org.tron.core.net.message.MessageTypes;
import org.tron.protos.Protocol.PbftMessage;
import org.tron.protos.Protocol.PbftMessage.Raw;
import org.tron.protos.Protocol.PbftMessage.Type;
import org.tron.protos.Protocol.SrList;

public abstract class PbftBaseMessage extends Message {

  protected PbftMessage pbftMessage;

  private boolean isSwitch;

  public PbftBaseMessage() {
  }

  public PbftBaseMessage(byte type, byte[] data) throws IOException, P2pException {
    super(type, data);
    this.pbftMessage = PbftMessage.parseFrom(getCodedInputStream(data));
    if (isFilter()) {
      compareBytes(data, pbftMessage.toByteArray());
    }
  }

  @Override
  public Class<?> getAnswerMessage() {
    return null;
  }

  public PbftMessage getPbftMessage() {
    return pbftMessage;
  }

  public PbftBaseMessage setPbftMessage(PbftMessage pbftMessage) {
    this.pbftMessage = pbftMessage;
    return this;
  }

  public boolean isSwitch() {
    return isSwitch;
  }

  public PbftBaseMessage setSwitch(boolean aSwitch) {
    isSwitch = aSwitch;
    return this;
  }

  public PbftBaseMessage setData(byte[] data) {
    this.data = data;
    return this;
  }

  public PbftBaseMessage setType(byte type) {
    this.type = type;
    return this;
  }

  public String getKey() {
    return getNo() + "_" + Hex.toHexString(pbftMessage.getRawData().getPublicKey().toByteArray());
  }

  public String getDataKey() {
    return getNo() + "_" + Hex.toHexString(pbftMessage.getRawData().getData().toByteArray());
  }

  public long getBlockNum() {
    return pbftMessage.getRawData().getBlockNum();
  }

  public abstract String getNo();

  public abstract PbftBaseMessage createMessage();

  public boolean validateSignature()
      throws SignatureException {
    byte[] hash = Sha256Hash.hash(getPbftMessage().getRawData().toByteArray());
    byte[] sigAddress = ECKey.signatureToAddress(hash, TransactionCapsule
        .getBase64FromByteString(getPbftMessage().getSign()));
    byte[] witnessAccountAddress = getPbftMessage().getRawData().getPublicKey().toByteArray();
    byte[] dataHash = Sha256Hash.hash(getPbftMessage().getRawData().getData().toByteArray());
    byte[] dataSignAddress = ECKey.signatureToAddress(dataHash,
        TransactionCapsule.getBase64FromByteString(getPbftMessage().getRawData().getDataSign()));
    return Arrays.equals(sigAddress, witnessAccountAddress) && Arrays
        .equals(dataSignAddress, witnessAccountAddress);
  }

  public PbftBaseMessage buildPrePareMessage() {
    return buildMessageCapsule(Type.PREPARE);
  }

  public PbftBaseMessage buildCommitMessage() {
    return buildMessageCapsule(Type.COMMIT);
  }

  private PbftBaseMessage buildMessageCapsule(Type type) {
    PbftBaseMessage pbftMessage = createMessage();
    Miner miner = Param.getInstance().getMiners().get(0);
    ECKey ecKey = ECKey.fromPrivate(miner.getPrivateKey());
    PbftMessage.Builder builder = PbftMessage.newBuilder();
    Raw.Builder rawBuilder = Raw.newBuilder();
    byte[] publicKey = ecKey.getAddress();
    byte[] dataSign = ecKey.sign(Sha256Hash.hash(getPbftMessage().getRawData().getData()
        .toByteArray())).toByteArray();
    rawBuilder.setBlockNum(getPbftMessage().getRawData().getBlockNum())
        .setPbftMsgType(type)
        .setTime(System.currentTimeMillis())
        .setPublicKey(ByteString.copyFrom(publicKey == null ? new byte[0] : publicKey))
        .setData(getPbftMessage().getRawData().getData())
        .setDataSign(ByteString.copyFrom(dataSign));
    Raw raw = rawBuilder.build();
    byte[] hash = Sha256Hash.hash(raw.toByteArray());
    ECDSASignature signature = ecKey.sign(hash);
    builder.setRawData(raw).setSign(ByteString.copyFrom(signature.toByteArray()));
    PbftMessage message = builder.build();
    pbftMessage.setType(getType().asByte())
        .setPbftMessage(message).setData(message.toByteArray());
    return pbftMessage;
  }

  @Override
  public String toString() {
    return "PbftMsgType:" + pbftMessage.getRawData().getPbftMsgType()
        + ", node address:" + Hex.toHexString(pbftMessage.getRawData().getPublicKey().toByteArray())
        + ", block num:" + pbftMessage.getRawData().getBlockNum()
        + ", data:" + getDataString()
        + ", " + super.toString();
  }

  public String getDataString() {
    return getType() == MessageTypes.PBFT_SR_MSG ? decode()
        : Hex.toHexString(pbftMessage.getRawData().getData().toByteArray());
  }

  private String decode() {
    try {
      SrList srList = SrList.parseFrom(pbftMessage.getRawData().getData().toByteArray());
      return "cycle = " + srList.getEpoch() + ", sr list = " + srList.getSrAddressList().stream().map(
          bytes -> WalletUtil.encode58Check(bytes.toByteArray())).collect(Collectors.toList());
    } catch (InvalidProtocolBufferException e) {
    }
    return "decode error";
  }
}
