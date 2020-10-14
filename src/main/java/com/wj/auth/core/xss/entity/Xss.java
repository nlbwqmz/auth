package com.wj.auth.core.xss.entity;

import java.util.Set;

/**
 * @author 魏杰
 * @since 2020/10/13
 */
public class Xss {

  private boolean queryEnable;
  private boolean bodyEnable;
  private Set<String> exclusions;

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
}
