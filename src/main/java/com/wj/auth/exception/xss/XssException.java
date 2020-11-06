package com.wj.auth.exception.xss;

import com.wj.auth.exception.AuthException;

/**
 * @author 魏杰
 * @since 2020/10/17
 */
public class XssException extends AuthException {

  private static final long serialVersionUID = -1636012677889012370L;

  public XssException() {
  }

  public XssException(String msg) {
    super(msg);
  }
}
