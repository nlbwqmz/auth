package com.wj.auth.core.security.handler;

import com.wj.auth.core.security.configuration.Logical;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class AnonInterceptorHandler implements InterceptorHandler {

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String[] auth,
      Logical logical,
      Set<String> userAuth) {
    return true;
  }

  @Override
  public String authenticate(HttpServletRequest request, HttpServletResponse response,
      String header) {
    return null;
  }

  @Override
  public boolean isDecodeToken() {
    return false;
  }

  @Override
  public boolean isRefreshToken() {
    return false;
  }

  @Override
  public boolean isAuthorize() {
    return false;
  }
}
