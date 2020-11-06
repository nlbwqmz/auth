package com.wj.auth.core.chain;

import com.google.common.collect.ImmutableSet;
import com.wj.auth.common.AuthHelper;
import com.wj.auth.common.FilterRange;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.XssConfiguration;
import com.wj.auth.core.xss.XssRequestWrapper;
import com.wj.auth.exception.xss.XssException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.MatchUtils;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author 魏杰
 * @since 0.0.1
 */
@Order(3)
@Component
public class XssAuthChain implements AuthChain {

  private final XssConfiguration xssConfiguration;
  private ImmutableSet<AuthHelper> xssIgnored;
  private ImmutableSet<AuthHelper> xssOnly;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public XssAuthChain(AuthAutoConfiguration authAutoConfiguration) {
    this.xssConfiguration = authAutoConfiguration.getXss();
  }

  public void setXss(Set<AuthHelper> xssSet, Set<AuthHelper> xssIgnoredSet) {
    Set<String> only = xssConfiguration.getOnly();
    Set<String> ignored = xssConfiguration.getIgnored();
    if (CollectionUtils.isNotBlank(only)) {
      xssSet.add(
          AuthHelper.otherBuilder().setPatterns(CollectionUtils.addUrlPrefix(only, contextPath))
              .build());
    }
    if (CollectionUtils.isNotBlank(ignored)) {
      xssIgnoredSet.add(AuthHelper.otherBuilder()
          .setPatterns(CollectionUtils.addUrlPrefix(ignored, contextPath)).build());
    }
    xssOnly = ImmutableSet.copyOf(xssSet);
    xssIgnored = ImmutableSet.copyOf(xssIgnoredSet);
  }

  @Override
  public void doFilter(ChainManager chain) {
    HttpServletRequest request = SubjectManager.getRequest();
    if (isDoXss(request)) {
      SubjectManager.setRequest(new XssRequestWrapper(request, xssConfiguration.isQueryEnable(),
          xssConfiguration.isBodyEnable()));
    }
    chain.doAuth();
  }

  /**
   * 是否执行xss过滤
   *
   * @param request
   */
  private boolean isDoXss(HttpServletRequest request) {
    if (request != null) {
      FilterRange defaultFilterRange = xssConfiguration.getFilterRange();
      String uri = request.getRequestURI();
      String method = request.getMethod();
      switch (defaultFilterRange) {
        case ALL:
          return !MatchUtils.matcher(xssIgnored, uri, method);
        case NONE:
          return MatchUtils.matcher(xssOnly, request.getRequestURI(), request.getMethod());
        default:
          throw new XssException("xss configuration defaultFilterRange cannot match");
      }
    } else {
      return false;
    }
  }
}
