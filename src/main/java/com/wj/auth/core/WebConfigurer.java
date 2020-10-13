package com.wj.auth.core;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author weijie
 * @since 2020/9/10
 */
@ConditionalOnBean(AuthRealm.class)
@Import({AuthManager.class, TokenFactory.class})
public class WebConfigurer implements WebMvcConfigurer {

  private final AuthManager authManager;

  public WebConfigurer(AuthManager authManager) {
    this.authManager = authManager;
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(authInterceptor()).addPathPatterns("/**")
        .order(Ordered.HIGHEST_PRECEDENCE);
  }

  public AuthInterceptor authInterceptor() {
    return new AuthInterceptor(authManager);
  }

}
