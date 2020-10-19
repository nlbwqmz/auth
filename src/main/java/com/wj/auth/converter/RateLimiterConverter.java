package com.wj.auth.converter;

import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration.Strategy;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

/**
 * 枚举注入
 * @author weijie
 * @since 2020/10/16
 */
@Configuration
public class RateLimiterConverter implements Converter<String, Strategy> {

  @Override
  public Strategy convert(String source) {
    return Strategy.valueOf(source);
  }
}
