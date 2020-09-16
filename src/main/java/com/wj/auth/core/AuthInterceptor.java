package com.wj.auth.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

/**
 * @Author: weijie
 * @Date: 2020/9/10
 */
public class AuthInterceptor extends HandlerInterceptorAdapter {

  private final AuthManager authManager;

  public AuthInterceptor(AuthManager authManager) {
    this.authManager = authManager;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
      Object handler) {
    SubjectManager.setRequest(request);
    SubjectManager.setResponse(response);
    if (authManager.authorizationVerification(request)) {
      authManager.authorityVerification(request);
    }
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
      Object handler, Exception ex) {
    SubjectManager.removeAll();
  }
}
