package com.wj.auth.core.xss.configuration;

import java.util.Set;

/**
 * @author 魏杰
 * @since 2020/10/13
 */
public class XssConfiguration {

  /**
   * 开启query过滤
   */
  private boolean queryEnable;
  /**
   * 开启body过滤
   */
  private boolean bodyEnable;
  /**
   * 若only为空，则exclusions中包含的路由不进行XSS过滤，其他路由正常过滤
   * 若only不为空，则exclusions失效
   */
  private Set<String> exclusions;

  /**
   * 若only不为空，则只有only中所包含的路由才进行XSS过滤，exclusions将失效
   */
  private Set<String> only;

  public boolean isQueryEnable() {
    return queryEnable;
  }

  public void setQueryEnable(boolean queryEnable) {
    this.queryEnable = queryEnable;
  }

  public boolean isBodyEnable() {
    return bodyEnable;
  }

  public void setBodyEnable(boolean bodyEnable) {
    this.bodyEnable = bodyEnable;
  }

  public Set<String> getExclusions() {
    return exclusions;
  }

  public void setExclusions(Set<String> exclusions) {
    this.exclusions = exclusions;
  }

  public Set<String> getOnly() {
    return only;
  }

  public void setOnly(Set<String> only) {
    this.only = only;
  }
}
