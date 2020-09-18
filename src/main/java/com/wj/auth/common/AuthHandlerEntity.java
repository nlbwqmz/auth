package com.wj.auth.common;

import com.wj.auth.core.AuthHandler;
import java.util.Set;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public class AuthHandlerEntity {
  private Set<RequestVerification> requestVerifications;
  private AuthHandler authHandler;
  private int order;

  public AuthHandlerEntity() {
  }

  public AuthHandlerEntity(Set<RequestVerification> requestVerifications,
      AuthHandler authHandler, int order) {
    this.requestVerifications = requestVerifications;
    this.authHandler = authHandler;
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

  public AuthHandler getAuthHandler() {
    return authHandler;
  }

  public AuthHandlerEntity setAuthHandler(AuthHandler authHandler) {
    this.authHandler = authHandler;
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
