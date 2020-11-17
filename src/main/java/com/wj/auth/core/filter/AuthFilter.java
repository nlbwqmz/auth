package com.wj.auth.core.filter;

import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.core.AuthRealm;
import com.wj.auth.core.chain.AuthChain;
import com.wj.auth.core.chain.ChainManager;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;

/**
 * 过滤器
 *
 * @author 魏杰
 * @since 0.0.2
 */
@Order(0)
@WebFilter(filterName = "authFilter", urlPatterns = "/*")
public class AuthFilter implements Filter {

  private final List<AuthChain> authChains;
  private final AuthRealm authRealm;
  private final boolean skipOptionsMethod;

  public AuthFilter(List<AuthChain> authChains, AuthRealm authRealm,
      AuthAutoConfiguration authAutoConfiguration) {
    this.authChains = authChains.stream().filter(AuthChain::isEnabled).collect(Collectors.toList());
    this.authRealm = authRealm;
    this.skipOptionsMethod = authAutoConfiguration.isSkipOptionsMethod();
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      HttpServletRequest httpServletRequest = (HttpServletRequest) request;
      HttpServletResponse httpServletResponse = (HttpServletResponse) response;
      SubjectManager.setRequest(httpServletRequest);
      SubjectManager.setResponse(httpServletResponse);
      new ChainManager(authChains, isOptionsAndSkip(httpServletRequest)).doAuth();
      chain.doFilter(SubjectManager.getRequest(), SubjectManager.getResponse());
    } catch (Exception e) {
      authRealm.handleException(SubjectManager.getRequest(), SubjectManager.getResponse(), e);
    } finally {
      SubjectManager.removeAll();
    }
  }

  private boolean isOptionsAndSkip(HttpServletRequest request) {
    return skipOptionsMethod && HttpMethod.OPTIONS.name().equals(request.getMethod());
  }
}
