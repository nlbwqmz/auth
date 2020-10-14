package com.wj.auth.core.security;

import com.wj.auth.common.SubjectManager;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/14
 */
@Order(1)
@Component
@WebFilter(filterName = "authFilter", urlPatterns = "/*")
public class AuthFilter implements Filter {

  private final AuthManager authManager;

  public AuthFilter(AuthManager authManager) {
    this.authManager = authManager;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    try {
      SubjectManager.setRequest(httpServletRequest);
      SubjectManager.setResponse(httpServletResponse);
      if (authManager.doHandler(httpServletRequest, httpServletResponse)) {
        chain.doFilter(request, response);
      }
    } catch (Exception e) {
      httpServletRequest.setAttribute("authError", e);
      httpServletRequest.getRequestDispatcher("/auth/error").forward(request, response);
    } finally {
      System.out.println("结束");
      SubjectManager.removeAll();
    }
  }
}
