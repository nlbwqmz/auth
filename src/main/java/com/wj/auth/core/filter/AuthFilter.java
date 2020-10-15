package com.wj.auth.core.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.security.AuthManager;
import com.wj.auth.core.xss.XssSerializer;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;

/**
 * 过滤器
 *
 * @author weijie
 * @since 2020/10/14
 */
@Order(1)
@Component
@WebFilter(filterName = "authFilter", urlPatterns = "/*")
public class AuthFilter implements Filter {

  private final AuthManager authManager;
  private final AuthAutoConfiguration authAutoConfiguration;

  public AuthFilter(AuthManager authManager, AuthAutoConfiguration authAutoConfiguration) {
    this.authManager = authManager;
    this.authAutoConfiguration = authAutoConfiguration;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    try {
      String s = null;
      s.equalsIgnoreCase("aaa");
      authManager.doAuth(httpServletRequest, httpServletResponse, chain);
    } catch (Exception e) {
      httpServletRequest.setAttribute("authError", e);
      httpServletRequest.getRequestDispatcher("/auth/error").forward(httpServletRequest, httpServletResponse);
    } finally {
      SubjectManager.removeAll();
    }
  }

  /**
   * body Xss 转义
   */
  @Bean
  @Primary
  @ConditionalOnProperty(prefix = "auth.xss", name = "body-enable", havingValue = "true")
  public ObjectMapper xssObjectMapper(Jackson2ObjectMapperBuilder builder) {
    ObjectMapper objectMapper = builder.createXmlMapper(false).build();
    SimpleModule xssModule = new SimpleModule("xssStringJsonSerializer");
    xssModule.addSerializer(new XssSerializer());
    objectMapper.registerModule(xssModule);
    return objectMapper;
  }
}
