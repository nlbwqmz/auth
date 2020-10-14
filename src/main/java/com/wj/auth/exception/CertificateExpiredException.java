package com.wj.auth.exception;

/**
 * 凭证过期异常
 *
 * @author weijie
 * @since 2020/9/11
 */
public class CertificateExpiredException extends AuthException {

  public CertificateExpiredException(String message) {
    super(message);
  }
}
