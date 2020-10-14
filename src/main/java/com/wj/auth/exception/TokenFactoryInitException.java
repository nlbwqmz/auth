package com.wj.auth.exception;

/**
 * @author weijie
 * @since 2020/9/15
 */
public class TokenFactoryInitException extends AuthException {

  public TokenFactoryInitException() {
    super("AuthTokenGenerate init error");
  }

  public TokenFactoryInitException(String msg) {
    super(msg);
  }
}
