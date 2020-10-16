package com.wj.auth.core.security.configuration;

/**
 * token所支持的算法
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
