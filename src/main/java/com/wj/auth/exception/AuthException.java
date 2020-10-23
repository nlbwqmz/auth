package com.wj.auth.exception;

/**
 * @author weijie
 * @since 2020/9/30
 */
public class AuthException extends RuntimeException {

  private static final long serialVersionUID = 4988644127541663322L;

  public AuthException() {
    super();
  }

  public AuthException(String msg) {
    super(msg);
  }

}
