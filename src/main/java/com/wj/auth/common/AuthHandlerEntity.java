package com.wj.auth.common;

import com.wj.auth.handler.AuthHandler;
import java.util.Set;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public class AuthHandlerEntity {
  private Set<RequestVerification> requestVerifications;
  private AuthHandler handler;
  private int order;

  public AuthHandlerEntity() {
  }

  public AuthHandlerEntity(Set<RequestVerification> requestVerifications,
      AuthHandler handler, int order) {
    this.requestVerifications = requestVerifications;
    this.handler = handler;
    this.order = order;
  }

  public Set<RequestVerification> getRequestVerifications() {
    return requestVerifications;
  }

  public AuthHandlerEntity setRequestVerifications(
      Set<RequestVerification> requestVerifications) {
    this.requestVerifications = requestVerifications;
    return this;
  }

  public AuthHandler getHandler() {
    return handler;
  }

  public AuthHandlerEntity setHandler(AuthHandler handler) {
    this.handler = handler;
    return this;
  }

  public int getOrder() {
    return order;
  }

  public AuthHandlerEntity setOrder(int order) {
    this.order = order;
    return this;
  }
}
