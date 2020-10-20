package com.wj.auth.configuration;

/**
 * 跨域配置
 * @Author 魏杰
 * @since 2020/10/15
 */
public class CorsConfiguration {

  private boolean enabled = true;
  private String accessControlAllowOrigin = "*";
  private String accessControlAllowHeaders = "*";
  private String accessControlAllowMethods = "PUT,POST,GET,DELETE,OPTIONS";
  private boolean accessControlAllowCredentials = false;
  private String accessControlMaxAge = "1800";

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getAccessControlAllowOrigin() {
    return accessControlAllowOrigin;
  }

  public void setAccessControlAllowOrigin(String accessControlAllowOrigin) {
    this.accessControlAllowOrigin = accessControlAllowOrigin;
  }

  public String getAccessControlAllowHeaders() {
    return accessControlAllowHeaders;
  }

  public void setAccessControlAllowHeaders(String accessControlAllowHeaders) {
    this.accessControlAllowHeaders = accessControlAllowHeaders;
  }

  public String getAccessControlAllowMethods() {
    return accessControlAllowMethods;
  }

  public void setAccessControlAllowMethods(String accessControlAllowMethods) {
    this.accessControlAllowMethods = accessControlAllowMethods;
  }

  public boolean getAccessControlAllowCredentials() {
    return accessControlAllowCredentials;
  }

  public void setAccessControlAllowCredentials(boolean accessControlAllowCredentials) {
    this.accessControlAllowCredentials = accessControlAllowCredentials;
  }

  public String getAccessControlMaxAge() {
    return accessControlMaxAge;
  }

  public void setAccessControlMaxAge(String accessControlMaxAge) {
    this.accessControlMaxAge = accessControlMaxAge;
  }
}
