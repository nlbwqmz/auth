package com.wj.auth.exception.rate;

import com.wj.auth.exception.AuthException;

/**
 * @author weijie
 * @since 2020/10/17
 */
public class RateLimiterException extends AuthException {

  public RateLimiterException() {
  }

  public RateLimiterException(String msg) {
    super(msg);
  }
}
