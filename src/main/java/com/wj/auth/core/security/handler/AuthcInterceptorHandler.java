package com.wj.auth.core.security.handler;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 魏杰
 * @Description:
 * @since 2020/9/18
 */
public class AuthcInterceptorHandler implements InterceptorHandler {

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String auth,
      Set<String> userAuth) {
    return true;
  }

  @Override
  public String authenticate(HttpServletRequest request,
      HttpServletResponse response, String header) {
    return request.getHeader(header);
  }
}