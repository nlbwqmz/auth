package com.wj.auth.exception;

/**
 * 凭证过期异常
 * @Author: weijie
 * @Date: 2020/9/11
 */
public class CertificateExpiredException extends RuntimeException {

  public CertificateExpiredException(String message) {
    super(message);
  }
}
