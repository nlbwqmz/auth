package com.wj.auth.core.rateLimiter.configuration;

/**
 * 限流配置
 *
 * @author weijie
 * @since 2020/10/16
 */
public class RateLimiterConfiguration {

  /**
   * 开启
   */
  private boolean enabled = false;
  /**
   * 阈值
   */
  private double threshold = 5;

  /**
   * 策略
   */
  private Strategy strategy = Strategy.NORMAL;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public double getThreshold() {
    return threshold;
  }

  public void setThreshold(double threshold) {
    this.threshold = threshold;
  }

  public Strategy getStrategy() {
    return strategy;
  }

  public void setStrategy(Strategy strategy) {
    this.strategy = strategy;
  }

  public enum Strategy {
    /**
     * 正常：全局限流
     */
    NORMAL,
    /**
     * IP：IP限流
     */
    IP
  }
}
