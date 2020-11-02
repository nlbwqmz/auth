package com.wj.auth.configuration;

/**
 * 跨域配置
 *
 * @author 魏杰
 * @since 2020/10/15
 */
public class CorsConfiguration {

  private boolean enabled = false;
  private String[] accessControlAllowOrigin = new String[]{"*"};
  private String[] accessControlAllowHeaders = new String[]{"*"};
  private String[] accessControlAllowMethods
      = new String[]{"PUT", "POST", "GET", "DELETE", "OPTIONS"};
  private Boolean accessControlAllowCredentials = false;
  private Long accessControlMaxAge = 1800L;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String[] getAccessControlAllowOrigin() {
    return accessControlAllowOrigin;
  }

  public void setAccessControlAllowOrigin(String[] accessControlAllowOrigin) {
    this.accessControlAllowOrigin = accessControlAllowOrigin;
  }

  public String[] getAccessControlAllowHeaders() {
    return accessControlAllowHeaders;
  }

  public void setAccessControlAllowHeaders(String[] accessControlAllowHeaders) {
    this.accessControlAllowHeaders = accessControlAllowHeaders;
  }

  public String[] getAccessControlAllowMethods() {
    return accessControlAllowMethods;
  }

  public void setAccessControlAllowMethods(String[] accessControlAllowMethods) {
    this.accessControlAllowMethods = accessControlAllowMethods;
  }

  public Boolean isAccessControlAllowCredentials() {
    return accessControlAllowCredentials;
  }

  public void setAccessControlAllowCredentials(Boolean accessControlAllowCredentials) {
    this.accessControlAllowCredentials = accessControlAllowCredentials;
  }

  public Long getAccessControlMaxAge() {
    return accessControlMaxAge;
  }

  public void setAccessControlMaxAge(Long accessControlMaxAge) {
    this.accessControlMaxAge = accessControlMaxAge;
  }
}
