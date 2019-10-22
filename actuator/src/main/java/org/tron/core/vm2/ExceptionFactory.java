package org.tron.core.vm2;

import static java.lang.String.format;

import org.tron.core.vm.program.Program;
import org.tron.core.vm.program.Program.OutOfMemoryException;


public class ExceptionFactory {

  private ExceptionFactory() {
  }

  public static final String VALIDATE_FOR_SMART_CONTRACT_FAILURE =
          "validateForSmartContract failure:%s";
  public static final String INVALID_TOKEN_ID_MSG = "not valid token id";


  public static StaticCallTransferException staticCallTransferException() {
    return new StaticCallTransferException(
        "constant cannot set call value or call token value.");
  }

  public static Program.StackTooSmallException tooSmallStack(int expectedSize, int actualSize) {
    return new Program.StackTooSmallException(
        "Expected stack size %d but actual %d;", expectedSize, actualSize);
  }

  public static Program.StackTooLargeException tooLargeStack(int expectedSize, int maxSize) {
    return new Program.StackTooLargeException(
        format("Expected stack size %d exceeds stack limit %d", expectedSize, maxSize)
    );
  }

  public static Program.TransferException tokenInvalid() {
    return new Program.TransferException(VALIDATE_FOR_SMART_CONTRACT_FAILURE, INVALID_TOKEN_ID_MSG);
  }

  public static Program.TransferException transferSuicideAllTokenException(String message) {
    return new Program.TransferException(
        "transfer all token or transfer all trx failed in suicide: %s", message);
  }

  public static Program.TransferException transferException(String message) {
    return new Program.TransferException(
        "transfer trx failed: %s", message);
  }

  public static Program.OutOfEnergyException notEnoughSpendEnergy(String hint, long needEnergy,
                                                                  long leftEnergy) {
    return new Program.OutOfEnergyException(
        "Not enough energy for '%s' executing: needEnergy[%d], leftEnergy[%d];",
        hint, needEnergy, leftEnergy);
  }

  public static Program.JVMStackOverFlowException jvmStackOverFlow() {
    return new Program.JVMStackOverFlowException();

  }

  public static Program.BytecodeExecutionException unknownThrowable(String message) {
    return new Program.BytecodeExecutionException(message);

  }

  public static OutOfMemoryException memoryOverflow(String op) {
    return new OutOfMemoryException("Out of Memory when '%s' operation executing", op);
  }


  public static class StaticCallTransferException extends Program.BytecodeExecutionException {

    public StaticCallTransferException(String message) {
      super(message);
    }
  }


}
