package com.wj.auth.converter;

import com.wj.auth.core.security.configuration.AlgorithmEnum;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

/**
 * 枚举注入
 *
 * @author weijie
 * @since 2020/10/16
 */
@Configuration
public class AlgorithmConverter implements Converter<String, AlgorithmEnum> {

  @Override
  public AlgorithmEnum convert(String source) {
    return AlgorithmEnum.valueOf(source);
  }
}
