package com.wj.auth.core.security.handler;

import com.wj.auth.core.security.configuration.Logical;
import com.wj.auth.exception.security.AuthSecurityException;
import com.wj.auth.utils.CollectionUtils;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class AuthInterceptorHandler implements InterceptorHandler {

  @Override
  public boolean authorize(HttpServletRequest request, HttpServletResponse response, String[] auth,
      Logical logical,
      Set<String> userAuth) {
    if (CollectionUtils.isBlank(userAuth)) {
      return false;
    }
    switch (logical) {
      case OR:
        return checkOr(userAuth, auth);
      case AND:
        return checkAnd(userAuth, auth);
      default:
        throw new AuthSecurityException("unknown exception");
    }
  }

  @Override
  public String authenticate(HttpServletRequest request, HttpServletResponse response,
      String header) {
    return request.getHeader(header);
  }

  private boolean checkOr(Set<String> userAuth, String[] auth) {
    for (String item : auth) {
      if (userAuth.contains(item)) {
        return true;
      }
    }
    return false;
  }

  private boolean checkAnd(Set<String> userAuth, String[] auth) {
    for (String item : auth) {
      if (!userAuth.contains(item)) {
        return false;
      }
    }
    return true;
  }
}
