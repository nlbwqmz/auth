package com.wj.auth.configuration;

import java.util.Set;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author weijie
 * @since 2020/10/16
 */
public class SecurityConfiguration {

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
  private TokenConfiguration token = new TokenConfiguration();

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

  public TokenConfiguration getToken() {
    return token;
  }

  public void setToken(TokenConfiguration token) {
    this.token = token;
  }
}
