package com.wj.auth.common;

import com.wj.auth.core.security.AuthRealm;
import com.wj.auth.core.security.AuthRunner;
import com.wj.auth.core.security.entity.Token;
import com.wj.auth.core.xss.entity.Xss;
import java.util.Set;
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
@Import(AuthRunner.class)
public class AuthAutoConfiguration {

  public final static String AUTH_PREFIX = "auth";
  public final static String ERROR_ATTRIBUTE = "authError";
  private static Logger log = LoggerFactory.getLogger(AuthAutoConfiguration.class);
  /**
   * Token头名称
   */
  private String header = "Authorization";
  /**
   * 免登录接口
   */
  private Set<String> anon;
  /**
   * 严格模式 true:所有请求都会被过滤，被springboot扫描到的请求按照设置过滤，未被扫描到的执行AuthcInterceptorHandler
   * false:只有被springboot扫描到的请求会被过滤
   */
  private boolean strict = true;
  /**
   * 是否开启注解
   */
  private boolean annotationEnabled = true;
  /**
   * token配置
   */
  @NestedConfigurationProperty
  private Token token = new Token();
  /**
   * xss配置
   */
  @NestedConfigurationProperty
  private Xss xss = new Xss();
  /**
   * 跨域配置
   */
  @NestedConfigurationProperty
  private Cors cors = new Cors();

  public AuthAutoConfiguration(@Autowired(required = false) AuthRealm authRealm) {
    if (authRealm == null && log.isWarnEnabled()) {
      log.warn("auth cannot be turned on, because AuthRealm is required.");
    }
  }

  public String getHeader() {
    return header;
  }

  public void setHeader(String header) {
    this.header = header;
  }

  public Set<String> getAnon() {
    return anon;
  }

  public void setAnon(Set<String> anon) {
    this.anon = anon;
  }

  public boolean isStrict() {
    return strict;
  }

  public void setStrict(boolean strict) {
    this.strict = strict;
  }

  public boolean isAnnotationEnabled() {
    return annotationEnabled;
  }

  public void setAnnotationEnabled(boolean annotationEnabled) {
    this.annotationEnabled = annotationEnabled;
  }

  public Token getToken() {
    return token;
  }

  public void setToken(Token token) {
    this.token = token;
  }

  public Xss getXss() {
    return xss;
  }

  public void setXss(Xss xss) {
    this.xss = xss;
  }

  public Cors getCors() {
    return cors;
  }

  public void setCors(Cors cors) {
    this.cors = cors;
  }
}
