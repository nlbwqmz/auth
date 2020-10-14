package com.wj.auth.core.security.entity;

import com.wj.auth.core.security.handler.InterceptorHandler;
import java.util.Set;

/**
 * @author weijie
 * @since 2020/9/18
 */
public class AuthHandlerEntity {

  private Set<RequestVerification> requestVerifications;
  private InterceptorHandler handler;
  private int order;

  public AuthHandlerEntity() {
  }

  public AuthHandlerEntity(Set<RequestVerification> requestVerifications,
      InterceptorHandler handler, int order) {
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

  public InterceptorHandler getHandler() {
    return handler;
  }

  public AuthHandlerEntity setHandler(InterceptorHandler handler) {
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
