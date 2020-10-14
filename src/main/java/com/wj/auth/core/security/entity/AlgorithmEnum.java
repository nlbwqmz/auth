package com.wj.auth.core.security.entity;

/**
 * @author weijie
 * @since 2020/9/15
 */
public enum AlgorithmEnum {
  RSA("RSA"),
  HMAC256("HMAC256");

  AlgorithmEnum(String value) {

  }

  public AlgorithmEnum get(String value) {
    return AlgorithmEnum.valueOf(value);
  }
}
