package com.wj.auth.core.rateLimiter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author weijie
 * @since 2020/10/16
 */
public interface RateLimiterCondition {

  /**
   * 获取限流条件
   */
  String getCondition(HttpServletRequest request, HttpServletResponse response);
}
