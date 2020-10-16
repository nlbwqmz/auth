package com.wj.auth.core.chain;

import com.google.common.collect.Maps;
import com.google.common.util.concurrent.RateLimiter;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration;
import com.wj.auth.exception.AuthException;
import java.util.Map;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(0)
@Component
public class RateLimiterChain implements Chain {

  private final RateLimiterConfiguration configuration;
  private final RateLimiter rateLimiter;
  private final Map<String, RateLimiter> ipRateLimiterMap = Maps.newConcurrentMap();

  public RateLimiterChain(AuthAutoConfiguration authAutoConfiguration) {
    this.configuration = authAutoConfiguration.getRateLimiter();
    this.rateLimiter = RateLimiter.create(configuration.getThreshold());
  }

  @Override
  public void doFilter(ChainManager chain) {
    if (configuration.isEnabled()) {
      switch (configuration.getStrategy()) {
        case NORMAL:
          normal();
          break;
        case IP:
          ip();
          break;
        default:
          throw new AuthException("unknown exception");
      }
    }
    chain.doAuth();
  }

  private void normal() {
    if (!rateLimiter.tryAcquire()) {
      throw new AuthException("busy service");
    }
  }

  private void ip() {
    String ip = getIp();
    if (ipRateLimiterMap.containsKey(ip)) {
      rateLimitCheck(ipRateLimiterMap.get(ip));
    } else {
      RateLimiter rateLimiter = RateLimiter.create(configuration.getThreshold());
      ipRateLimiterMap.put(ip, rateLimiter);
      rateLimitCheck(rateLimiter);
    }
  }

  private void rateLimitCheck(RateLimiter rateLimiter) {
    if (!rateLimiter.tryAcquire()) {
      throw new AuthException("busy service");
    }
  }

  /**
   * TODO 获取IP地址
   */
  private String getIp() {
    return "";
  }
}
