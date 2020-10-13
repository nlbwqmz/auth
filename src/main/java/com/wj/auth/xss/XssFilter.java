package com.wj.auth.xss;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.wj.auth.common.AuthConfiguration;
import com.wj.auth.utils.AuthUtils;
import com.wj.auth.utils.CollectionUtils;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/13
 */
@Component
//@ConditionalOnProperty(prefix = "auth.xss", name = "enable", havingValue = "true")
public class XssFilter implements Filter {

  private final AuthConfiguration authConfiguration;

  private Set<String> exclusions;

  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public XssFilter(AuthConfiguration authConfiguration) {
    this.authConfiguration = authConfiguration;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {

  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    if (exclusions == null) {
      Set<String> config = Optional.ofNullable(authConfiguration.getXss().getExclusions())
          .orElse(Sets.newHashSet());
      if (!Strings.isNullOrEmpty(contextPath)) {
        exclusions = CollectionUtils.addUrlPrefix(config, contextPath);
      } else {
        exclusions = config;
      }
    }
    String uri = req.getRequestURI();
    if (AuthUtils.matcher(exclusions, uri)) {
      chain.doFilter(new XssAndSqlHttpServletRequestWrapper(req), response);
    } else {
      chain.doFilter(request, response);
    }
  }

  @Override
  public void destroy() {

  }

  /**
   * 过滤json类型的
   *
   * @param builder
   * @return
   */
  @Bean
  @Primary
  @ConditionalOnProperty(prefix = "auth.xss", name = "bodyEnable", havingValue = "true")
  public ObjectMapper xssObjectMapper(Jackson2ObjectMapperBuilder builder) {
    ObjectMapper objectMapper = builder.createXmlMapper(false).build();
    SimpleModule xssModule = new SimpleModule("XssStringJsonSerializer");
    xssModule.addSerializer(new XssStringJsonSerializer());
    objectMapper.registerModule(xssModule);
    return objectMapper;
  }

}
