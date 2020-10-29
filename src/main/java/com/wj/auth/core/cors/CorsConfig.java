package com.wj.auth.core.cors;

import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.CorsConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author weijie
 * @since 2020/5/7
 */

@Configuration
@ConditionalOnProperty(prefix = "auth.cors", name = "enabled", havingValue = "true")
public class CorsConfig implements WebMvcConfigurer {

  private final CorsConfiguration corsConfiguration;

  public CorsConfig(AuthAutoConfiguration authAutoConfiguration) {
    corsConfiguration = authAutoConfiguration.getCors();
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    if (corsConfiguration.isEnabled()) {
      registry.addMapping("/**")
          .allowedOrigins(corsConfiguration.getAccessControlAllowOrigin())
          .allowedMethods(corsConfiguration.getAccessControlAllowMethods())
          .allowCredentials(corsConfiguration.isAccessControlAllowCredentials())
          .allowedHeaders(corsConfiguration.getAccessControlAllowHeaders())
          .maxAge(corsConfiguration.getAccessControlMaxAge());
    }

  }
}
