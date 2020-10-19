package com.wj.auth.core.rateLimiter;

import javax.servlet.http.HttpServletRequest;

/**
 * @author weijie
 * @since 2020/10/16
 */
@FunctionalInterface
public interface RateLimiterCondition {

  /**
   * 获取限流条件
   */
  String getCondition(HttpServletRequest request, Object subject);
}
