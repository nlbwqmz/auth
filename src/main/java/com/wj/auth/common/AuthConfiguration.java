package com.wj.auth.common;

import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * @author weijie
 * @since 2020/9/27
 */
@ConfigurationProperties("auth")
public class AuthConfiguration {

  /**
   * Token头名称
   */
  private String header = "Authorization";
  /**
   * 免登录接口
   */
  private Set<String> anon;

  /**
   * 是否开启注解
   */
  private boolean annotationEnabled = true;

  @NestedConfigurationProperty
  private Token token = new Token();

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

  public Token getToken() {
    return token;
  }

  public void setToken(Token token) {
    this.token = token;
  }

  public boolean isAnnotationEnabled() {
    return annotationEnabled;
  }

  public void setAnnotationEnabled(boolean annotationEnabled) {
    this.annotationEnabled = annotationEnabled;
  }
}
