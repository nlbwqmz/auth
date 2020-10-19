package com.wj.auth.exception.xss;

import com.wj.auth.exception.AuthException;

/**
 * @author weijie
 * @since 2020/10/17
 */
public class XssException extends AuthException {

  public XssException() {
  }

  public XssException(String msg) {
    super(msg);
  }
}
