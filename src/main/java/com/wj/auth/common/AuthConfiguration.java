package com.wj.auth.common;

import com.wj.auth.core.security.entity.Token;
import com.wj.auth.core.xss.entity.Xss;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

/**
 * @author weijie
 * @since 2020/9/27
 */
@Configuration
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

  @NestedConfigurationProperty
  private Xss xss = new Xss();

  @NestedConfigurationProperty
  private Cors cors = new Cors();

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
