package com.wj.auth.exception.security;

/**
 * 凭证未找到异常
 *
 * @author weijie
 * @since 2020/9/11
 */
public class CertificateNotFoundException extends AuthSecurityException {

  public CertificateNotFoundException() {
    super("certificate not found");
  }
}
