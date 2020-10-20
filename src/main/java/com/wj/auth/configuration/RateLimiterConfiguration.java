package com.wj.auth.configuration;

import com.wj.auth.common.FilterRange;
import java.util.Set;

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
   * 忽略
   */
  private Set<String> ignored;

  /**
   * 只有这些接口才限流
   */
  private Set<String> only;

  /**
   * 策略
   */
  private Strategy strategy = Strategy.NORMAL;

  /**
   * 默认过滤范围
   */
  private FilterRange defaultFilterRange = FilterRange.ALL;

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

  public Set<String> getIgnored() {
    return ignored;
  }

  public void setIgnored(Set<String> ignored) {
    this.ignored = ignored;
  }

  public Set<String> getOnly() {
    return only;
  }

  public void setOnly(Set<String> only) {
    this.only = only;
  }

  public FilterRange getDefaultFilterRange() {
    return defaultFilterRange;
  }

  public void setDefaultFilterRange(FilterRange defaultFilterRange) {
    this.defaultFilterRange = defaultFilterRange;
  }

  public enum Strategy {
    /**
     * 正常：全局限流
     */
    NORMAL,
    /**
     * IP：IP限流
     */
    IP,
    /**
     * 自定义
     */
    CUSTOM
  }
}
