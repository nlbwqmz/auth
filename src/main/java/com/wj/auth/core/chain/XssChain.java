package com.wj.auth.core.chain;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.collect.ImmutableSet;
import com.google.common.html.HtmlEscapers;
import com.wj.auth.common.AuthHelper;
import com.wj.auth.common.FilterRange;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.XssConfiguration;
import com.wj.auth.core.xss.XssRequestWrapper;
import com.wj.auth.exception.xss.XssException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.MatchUtils;
import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(3)
@Component
public class XssChain extends JsonSerializer<String> implements Chain {

  private final XssConfiguration xssConfiguration;
  private ImmutableSet<AuthHelper> xssIgnored;
  private ImmutableSet<AuthHelper> xssOnly;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public XssChain(AuthAutoConfiguration authAutoConfiguration) {
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
    if (xssConfiguration.isQueryEnable()) {
      HttpServletRequest request = SubjectManager.getRequest();
      if (isDoXss(request)) {
        SubjectManager.setRequest(new XssRequestWrapper(request));
      }
    } else {
      chain.doAuth();
    }
  }

  @Override
  public Class<String> handledType() {
    return String.class;
  }

  @Override
  public void serialize(String value, JsonGenerator jsonGenerator,
      SerializerProvider serializerProvider) throws IOException {
    if (xssConfiguration.isBodyEnable() && isDoXss(SubjectManager.getRequest()) && value != null) {
      jsonGenerator.writeString(HtmlEscapers.htmlEscaper().escape(value));
    } else {
      jsonGenerator.writeString(value);
    }
  }

  /**
   * 是否执行xss过滤
   *
   * @param request
   */
  private boolean isDoXss(HttpServletRequest request) {
    if (request != null) {
      FilterRange defaultFilterRange = xssConfiguration.getDefaultFilterRange();
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

  /**
   * body XssConfiguration 转义
   */
  @Bean
  @Primary
  @ConditionalOnProperty(prefix = "auth.xss", name = "body-enable", havingValue = "true")
  public ObjectMapper xssBody(Jackson2ObjectMapperBuilder builder) {
    ObjectMapper objectMapper = builder.createXmlMapper(false).build();
    SimpleModule xssModule = new SimpleModule("xssSerializer");
    xssModule.addSerializer(this);
    objectMapper.registerModule(xssModule);
    return objectMapper;
  }
}
