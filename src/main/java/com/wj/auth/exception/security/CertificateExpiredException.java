package com.wj.auth.exception.security;

/**
 * 凭证过期异常
 *
 * @author weijie
 * @since 2020/9/11
 */
public class CertificateExpiredException extends AuthSecurityException {

  public CertificateExpiredException(String message) {
    super(message);
  }
}
