package com.wj.auth.core.security.handler;

import com.wj.auth.utils.CollectionUtils;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author weijie
 * @since 2020/9/18
 */
public class AuthInterceptorHandler implements InterceptorHandler {

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String auth,
      Set<String> userAuth) {
    if (CollectionUtils.isBlank(userAuth)) {
      return false;
    }
    return userAuth.contains(auth);
  }

  @Override
  public String authenticate(HttpServletRequest request, HttpServletResponse response,
      String header) {
    return request.getHeader(header);
  }
}
