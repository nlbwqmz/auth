package com.wj.auth.exception;

/**
 * @author weijie
 * @date 2020/9/14
 */
public class CertificateException extends RuntimeException {

  public CertificateException() {
    super("凭证异常！");
  }
}
