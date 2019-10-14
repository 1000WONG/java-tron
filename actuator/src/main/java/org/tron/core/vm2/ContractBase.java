package org.tron.core.vm2;

import static org.apache.commons.lang3.ArrayUtils.nullToEmpty;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.tron.common.runtime.InternalTransaction;
import org.tron.common.runtime.ProgramResult;
import org.tron.common.runtime.vm.DataWord;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.vm2.interpretor.Op;

@Slf4j(topic = "VM2")
@Data
public class ContractBase {

  @Data
  class BlockInfo {
    byte[] lastHash = null;
    byte[] coinbase = null;
    long timestamp = 0L;
    long number = -1L;
    int difficulty = 0;
  }

  /**
   * place to save interpretor call info
   */
  @Data
  class CallInfo {
    boolean fromVM = false;
    boolean delegate = false;
    boolean isTokenTransfer = false;
    long endowment = 0;
    byte[] newAddress;//for create and create2 op
    boolean isCreate2;


  }


  InternalTransaction.TrxType trxType;

  private boolean isStatic;

  private long energyLimit;

  private long vmStartInUs;

  private long vmShouldEndInUs;

  long callValue = 0;

  long tokenValue = 0;

  long tokenId = 0;

  AccountCapsule creator;

  AccountCapsule caller;

  private byte[] contractAddress;

  byte[] callerAddress;

  byte[] origin;

  private byte[] ops;

  private byte[] rootTransactionId;

  private InternalTransaction internalTransaction;

  private byte[] msgData;

  ProgramResult programResult = new ProgramResult();

  BlockInfo blockInfo = new BlockInfo();

  private ProgramPrecompile programPrecompile;


  private CallInfo callInfo = new CallInfo();

  List<String> opHistory = new ArrayList<>();



  public void addOpHistory(String s){
    opHistory.add(s);
  }

  public void setOps(byte[] ops) {
    this.ops = nullToEmpty(ops);
  }

  public void setContractAddress(byte[] contractAddress) {
    this.contractAddress = contractAddress;
  }

  public long getEnergylimitLeftLong() {
    return energyLimit - programResult.getEnergyUsed();
  }

  public DataWord getEnergyLimitLeft() {
    return new DataWord(energyLimit - programResult.getEnergyUsed());
  }

  public byte[] getCode() {
    return ops.clone();
  }

  public ProgramPrecompile getProgramPrecompile() {
    if (programPrecompile == null) {
      programPrecompile = ProgramPrecompile.compile(ops);
    }
    return programPrecompile;
  }


  @Slf4j(topic = "VM2")
  public static class ProgramPrecompile {

    private Set<Integer> jumpdest = new HashSet<>();

    public static ProgramPrecompile compile(byte[] ops) {
      ProgramPrecompile ret = new ProgramPrecompile();
      for (int i = 0; i < ops.length; ++i) {

        Op op = Op.code(ops[i]);
        if (op == null) {
          continue;
        }

        if (op.equals(Op.JUMPDEST)) {
          logger.debug("JUMPDEST:" + i);
          ret.jumpdest.add(i);
        }

        if (op.asInt() >= Op.PUSH1.asInt() && op.asInt() <= Op.PUSH32.asInt()) {
          i += op.asInt() - Op.PUSH1.asInt() + 1;
        }
      }
      return ret;
    }

    public static byte[] getCode(byte[] ops) {
      for (int i = 0; i < ops.length; ++i) {

        Op op = Op.code(ops[i]);
        if (op == null) {
          continue;
        }

        if (op.equals(Op.RETURN)) {
          logger.debug("return");
        }

        if (op.equals(Op.RETURN) && i + 1 < ops.length && Op.code(ops[i + 1]) != null
            && Op.code(ops[i + 1]).equals(Op.STOP)) {
          byte[] ret;
          i++;
          ret = new byte[ops.length - i - 1];

          System.arraycopy(ops, i + 1, ret, 0, ops.length - i - 1);
          return ret;
        }

        if (op.asInt() >= Op.PUSH1.asInt() && op.asInt() <= Op.PUSH32.asInt()) {
          i += op.asInt() - Op.PUSH1.asInt() + 1;
        }
      }
      return new byte[0];

    }

    public boolean hasJumpDest(int pc) {
      return jumpdest.contains(pc);
    }


  }

}
