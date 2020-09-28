package com.wj.auth.handler;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 魏杰
 * @date 2020/9/18
 * @Description:
 */
public class AuthcAuthHandler implements AuthHandler{

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String auth, Set<String> userAuth) {
    return true;
  }

  @Override
  public String authenticate(HttpServletRequest request,
      HttpServletResponse response, String header) {
    return request.getHeader(header);
  }
}
