package com.wj.auth.handler;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author weijie
 * @date 2020/9/18
 */
public class DefaultAuthHandler implements AuthHandler{

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String auth, Set<String> userAuth) {
    return userAuth.contains(auth);
  }

  @Override
  public String authenticate(HttpServletRequest request, HttpServletResponse response, String header) {
    return request.getHeader(header);
  }
}
