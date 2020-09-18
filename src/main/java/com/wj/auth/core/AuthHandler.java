package com.wj.auth.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public interface AuthHandler {

  /**
   * 权限验证
   * @return
   */
  boolean authorityVerification(HttpServletRequest request, HttpServletResponse response);

  /**
   * 认证
   * @return
   */
  boolean authorizationVerification(HttpServletRequest request, HttpServletResponse response);
}
