package com.wj.auth.common;

import com.wj.auth.core.Run;
import com.wj.auth.core.cors.configuration.CorsConfiguration;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration;
import com.wj.auth.core.security.AuthRealm;
import com.wj.auth.core.security.configuration.SecurityConfiguration;
import com.wj.auth.core.xss.configuration.XssConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
public class AuthAutoConfiguration {

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

  public AuthAutoConfiguration(@Autowired(required = false) AuthRealm authRealm) {
    if (authRealm == null && log.isWarnEnabled()) {
      log.warn("auth cannot be turned on, because AuthRealm is required.");
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
