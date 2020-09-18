package com.wj.auth.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public class FreeLoginAuthHandler implements AuthHandler{

  @Override
  public boolean authorityVerification(HttpServletRequest request, HttpServletResponse response) {
    return false;
  }

  @Override
  public boolean authorizationVerification(HttpServletRequest request, HttpServletResponse response) {
    return false;
  }
}
