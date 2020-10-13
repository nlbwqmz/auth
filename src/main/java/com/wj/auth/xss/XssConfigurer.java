package com.wj.auth.xss;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

/**
 * @Author: 魏杰
 * @Date: 2020/10/13
 * @Description:
 */
//@ConditionalOnProperty(prefix = "auth.xss", name = "enable", havingValue = "true")
@Component
public class XssConfigurer {

  private final XssFilter xssFilter;

  public XssConfigurer(XssFilter xssFilter) {
    System.out.println(xssFilter);
    this.xssFilter = xssFilter;
  }

  @Bean
  public FilterRegistrationBean filterRegistrationBean() {
    FilterRegistrationBean bean = new FilterRegistrationBean();
    bean.setFilter(xssFilter);
    bean.addUrlPatterns("/**");
    return bean;
  }
}
