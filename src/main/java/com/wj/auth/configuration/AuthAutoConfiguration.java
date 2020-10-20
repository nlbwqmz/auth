package com.wj.auth.configuration;

import com.wj.auth.configuration.RateLimiterConfiguration.Strategy;
import com.wj.auth.core.Run;
import com.wj.auth.core.rateLimiter.RateLimiterCondition;
import com.wj.auth.core.security.SecurityRealm;
import com.wj.auth.exception.rate.RateLimiterException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Auth 配置类
 *
 * @author weijie
 * @since 2020/9/27
 */
@Configuration
@ConfigurationProperties(AuthAutoConfiguration.AUTH_PREFIX)
@Import(Run.class)
public class AuthAutoConfiguration implements InitializingBean {

  public final static String AUTH_PREFIX = "auth";
  public final static String ERROR_ATTRIBUTE = "authError";
  private static Logger log = LoggerFactory.getLogger(AuthAutoConfiguration.class);

  /**
   * 授权认证配置
   */
  @NestedConfigurationProperty
  private SecurityConfiguration security = new SecurityConfiguration();

  /**
   * xss配置
   */
  @NestedConfigurationProperty
  private XssConfiguration xss = new XssConfiguration();
  /**
   * 跨域配置
   */
  @NestedConfigurationProperty
  private CorsConfiguration cors = new CorsConfiguration();

  /**
   * 限流配置
   */
  @NestedConfigurationProperty
  private RateLimiterConfiguration rateLimiter = new RateLimiterConfiguration();

  private final RateLimiterCondition rateLimiterCondition;

  public AuthAutoConfiguration(@Autowired(required = false) SecurityRealm securityRealm,
      @Autowired(required = false) RateLimiterCondition rateLimiterCondition) {
    if (securityRealm == null && log.isWarnEnabled()) {
      log.warn("auth cannot be turned on, because SecurityRealm is required.");
    }
    this.rateLimiterCondition = rateLimiterCondition;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    checkRateLimiterConfiguration();
  }

  private void checkRateLimiterConfiguration() {
    if (rateLimiter.isEnabled()) {
      if (rateLimiter.getThreshold() < 1) {
        throw new RateLimiterException(
            "The minimum rate limit threshold is 1, and the default is 5");
      }
      if (rateLimiter.getStrategy() == Strategy.CUSTOM && rateLimiterCondition == null) {
        throw new RateLimiterException(
            "rate limiter strategy is CUSTOM,so bean RateLimiterCondition is required.");
      }
    }
  }

  public SecurityConfiguration getSecurity() {
    return security;
  }

  public void setSecurity(
      SecurityConfiguration security) {
    this.security = security;
  }

  public static String getAuthPrefix() {
    return AUTH_PREFIX;
  }

  public static String getErrorAttribute() {
    return ERROR_ATTRIBUTE;
  }

  public static Logger getLog() {
    return log;
  }

  public static void setLog(Logger log) {
    AuthAutoConfiguration.log = log;
  }

  public XssConfiguration getXss() {
    return xss;
  }

  public void setXss(XssConfiguration xss) {
    this.xss = xss;
  }

  public CorsConfiguration getCors() {
    return cors;
  }

  public void setCors(CorsConfiguration cors) {
    this.cors = cors;
  }

  public RateLimiterConfiguration getRateLimiter() {
    return rateLimiter;
  }

  public void setRateLimiter(
      RateLimiterConfiguration rateLimiter) {
    this.rateLimiter = rateLimiter;
  }
}
