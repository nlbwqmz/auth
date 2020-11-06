package com.wj.auth.core.filter;

import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.chain.AuthChain;
import com.wj.auth.core.chain.ChainManager;
import java.io.IOException;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;

/**
 * 过滤器
 *
 * @author 魏杰
 * @since 0.0.1
 */
@Order(0)
@WebFilter(filterName = "authFilter", urlPatterns = "/*")
public class AuthFilter implements Filter {

  private final List<AuthChain> authChains;

  public AuthFilter(List<AuthChain> authChains) {
    this.authChains = authChains;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      SubjectManager.setRequest((HttpServletRequest) request);
      SubjectManager.setResponse((HttpServletResponse) response);
      new ChainManager(authChains).doAuth();
      chain.doFilter(SubjectManager.getRequest(), SubjectManager.getResponse());
    } catch (Exception e) {
      SubjectManager.getRequest().setAttribute("authError", e);
      SubjectManager.getRequest().getRequestDispatcher("/auth/error")
          .forward(SubjectManager.getRequest(), SubjectManager.getResponse());
    } finally {
      SubjectManager.removeAll();
    }
  }
}
