package org.tron.core.db;

import com.google.common.primitives.Bytes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;
import org.tron.core.capsule.PbftSignCapsule;

import java.util.Arrays;

@Slf4j
@Component
public class PbftSignDataStore extends TronDatabase<PbftSignCapsule> {

  public PbftSignDataStore() {
    super("pbft-sign-data");
  }

  @Override
  public void put(byte[] key, PbftSignCapsule item) {
    dbSource.putData(key, item.getData());
  }

  @Override
  public PbftSignCapsule get(byte[] key) {
    byte[] data = dbSource.getData(key);
    if (ByteUtil.isNullOrZeroArray(data)) {
      return null;
    }
    return new PbftSignCapsule(data);
  }

  @Override
  public void delete(byte[] key) {
    dbSource.deleteData(key);
  }

  @Override
  public boolean has(byte[] key) {
    return dbSource.getData(key) != null;
  }

  public void putSrSignData(long cycle, PbftSignCapsule item) {
    put(buildSrSignKey(cycle), item);
  }

  public PbftSignCapsule getSrSignData(long cycle) {
    return get(buildSrSignKey(cycle));
  }

  public void putBlockSignData(long blockNum, PbftSignCapsule item) {
    put(buildBlockSignKey(blockNum), item);
  }

  public PbftSignCapsule getBlockSignData(long blockNum) {
    return get(buildBlockSignKey(blockNum));
  }

  private byte[] buildSrSignKey(long cycle) {
    return Bytes.concat( "SrSign_".getBytes(), ByteArray.fromLong(cycle));
  }

  private byte[] buildBlockSignKey(long blockNum) {
    return Bytes.concat( "BlockSign_".getBytes(), ByteArray.fromLong(blockNum));
  }
}
