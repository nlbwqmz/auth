package com.wj.auth.core.security.configuration;

import com.wj.auth.common.AuthHelper;
import com.wj.auth.core.security.handler.InterceptorHandler;
import java.util.Set;

/**
 * @author weijie
 * @since 2020/9/18
 */
public class AuthHandlerEntity {

  private Set<AuthHelper> authHelpers;
  private InterceptorHandler handler;
  private int order;

  public AuthHandlerEntity() {
  }

  public AuthHandlerEntity(Set<AuthHelper> authHelpers,
      InterceptorHandler handler, int order) {
    this.authHelpers = authHelpers;
    this.handler = handler;
    this.order = order;
  }

  public Set<AuthHelper> getAuthHelpers() {
    return authHelpers;
  }

  public AuthHandlerEntity setAuthHelpers(
      Set<AuthHelper> authHelpers) {
    this.authHelpers = authHelpers;
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
