package com.wj.auth.core.chain;

import com.google.common.collect.Maps;
import com.google.common.util.concurrent.RateLimiter;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.rateLimiter.RateLimiterCondition;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration.Strategy;
import com.wj.auth.exception.AuthException;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
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
  private RateLimiter rateLimiter;
  private final Map<String, RateLimiter> ipRateLimiterMap = Maps.newConcurrentMap();
  private final RateLimiterCondition rateLimiterCondition;

  public RateLimiterChain(AuthAutoConfiguration authAutoConfiguration,
      @Autowired(required = false) RateLimiterCondition rateLimiterCondition) {
    this.configuration = authAutoConfiguration.getRateLimiter();
    this.rateLimiterCondition = rateLimiterCondition;
    checkConfiguration();
  }

  private void checkConfiguration() {
    if (configuration.isEnabled()) {
      if (configuration.getThreshold() < 1) {
        throw new AuthException("The minimum rate limit threshold is 1, and the default is 5");
      }
      if (configuration.getStrategy() == Strategy.CUSTOM && rateLimiterCondition == null) {
        throw new AuthException(
            "rate limiter strategy is CUSTOM,so bean RateLimiterCondition is required.");
      }
      if (configuration.getStrategy() == Strategy.NORMAL) {
        this.rateLimiter = RateLimiter.create(configuration.getThreshold());
      }
    }
  }

  @Override
  public void doFilter(ChainManager chain) {
    if (configuration.isEnabled()) {
      switch (configuration.getStrategy()) {
        case NORMAL:
          normal();
          break;
        case IP:
          condition(getIp());
          break;
        case CUSTOM:
          condition(rateLimiterCondition
              .getCondition(SubjectManager.getRequest(), SubjectManager.getResponse()));
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

  private void condition(String condition) {
    if (ipRateLimiterMap.containsKey(condition)) {
      rateLimitCheck(ipRateLimiterMap.get(condition));
    } else {
      RateLimiter rateLimiter = RateLimiter.create(configuration.getThreshold());
      ipRateLimiterMap.put(condition, rateLimiter);
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
