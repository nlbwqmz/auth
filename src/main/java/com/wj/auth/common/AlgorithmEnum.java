package com.wj.auth.common;

/**
 * @author weijie
 * @date 2020/9/15
 */
public enum AlgorithmEnum {
  RSA("RSA"),
  HMAC256("HMAC256");

  AlgorithmEnum(String value){

  }
  public AlgorithmEnum get(String value){
    return AlgorithmEnum.valueOf(value);
  }
}
