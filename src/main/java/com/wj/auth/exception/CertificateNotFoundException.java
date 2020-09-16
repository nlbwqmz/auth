package com.wj.auth.exception;

/**
 * 凭证未找到异常
 * @Author: weijie
 * @Date: 2020/9/11
 */
public class CertificateNotFoundException extends RuntimeException{
  public CertificateNotFoundException() {
    super("未找到凭证！");
  }
}
