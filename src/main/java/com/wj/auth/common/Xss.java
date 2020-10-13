package com.wj.auth.common;

import java.util.Set;

/**
 * @Author: 魏杰
 * @Date: 2020/10/13
 * @Description:
 */
public class Xss {

  private boolean enable;
  private boolean bodyEnable;
  private Set<String> exclusions;

  public boolean isEnable() {
    return enable;
  }

  public void setEnable(boolean enable) {
    this.enable = enable;
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
