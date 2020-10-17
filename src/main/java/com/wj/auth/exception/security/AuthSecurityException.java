package com.wj.auth.exception.security;

import com.wj.auth.exception.AuthException;

/**
 * @author weijie
 * @since 2020/10/17
 */
public class AuthSecurityException extends AuthException {

  public AuthSecurityException() {
  }

  public AuthSecurityException(String msg) {
    super(msg);
  }
}
