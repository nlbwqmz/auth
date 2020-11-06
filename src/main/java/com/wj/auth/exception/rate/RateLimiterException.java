package com.wj.auth.exception.rate;

import com.wj.auth.exception.AuthException;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class RateLimiterException extends AuthException {

  private static final long serialVersionUID = -747170999759162570L;

  public RateLimiterException() {
  }

  public RateLimiterException(String msg) {
    super(msg);
  }
}
