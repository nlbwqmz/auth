package com.wj.auth.core.chain;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.collect.Sets;
import com.google.common.html.HtmlEscapers;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.xss.XssRequestWrapper;
import com.wj.auth.core.xss.entity.Xss;
import com.wj.auth.utils.AuthUtils;
import com.wj.auth.utils.CollectionUtils;
import java.io.IOException;
import java.util.Set;
import javax.annotation.PostConstruct;
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
@Order(2)
@Component
public class XssChain extends JsonSerializer<String> implements Chain{

  private final AuthAutoConfiguration authAutoConfiguration;
  private Set<String> xssExclusions = Sets.newHashSet();
  private Set<String> xssOnly = Sets.newHashSet();
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public XssChain(AuthAutoConfiguration authAutoConfiguration) {
    this.authAutoConfiguration = authAutoConfiguration;
  }

  @PostConstruct
  public void init() {
    Xss xss = authAutoConfiguration.getXss();
    Set<String> only = xss.getOnly();
    if (CollectionUtils.isNotBlank(only)) {
      xssOnly = CollectionUtils.addUrlPrefix(only, contextPath);
    } else {
      Set<String> exclusions = xss.getExclusions();
      if (CollectionUtils.isNotBlank(exclusions)) {
        xssExclusions = CollectionUtils.addUrlPrefix(exclusions, contextPath);
      }
    }
  }
  @Override
  public void doFilter(ChainManager chain) {
    HttpServletRequest request = SubjectManager.getRequest();
    if (isDoXss(request.getRequestURI())) {
      SubjectManager.setRequest(new XssRequestWrapper(request));
    }
    chain.doAuth();
  }
  @Override
  public Class<String> handledType() {
    return String.class;
  }

  @Override
  public void serialize(String value, JsonGenerator jsonGenerator,
      SerializerProvider serializerProvider) throws IOException {
    if (isDoXss(SubjectManager.getRequest().getRequestURI())) {
      if (value != null) {
        jsonGenerator.writeString(HtmlEscapers.htmlEscaper().escape(value));
      }
    } else {
      jsonGenerator.writeString(value);
    }
  }

  private boolean isDoXss(String uri) {
    return authAutoConfiguration.getXss().isQueryEnable() && (
        (CollectionUtils.isNotBlank(xssOnly) && AuthUtils.matcher(xssOnly, uri))
            || (CollectionUtils.isBlank(xssOnly) && !AuthUtils.matcher(xssExclusions, uri)));
  }

  /**
   * body Xss 转义
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
