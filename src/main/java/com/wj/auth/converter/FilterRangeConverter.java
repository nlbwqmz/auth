package com.wj.auth.converter;

import com.wj.auth.common.FilterRange;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

/**
 * @author weijie
 * @since 2020/10/19
 */
@Configuration
public class FilterRangeConverter implements Converter<String, FilterRange> {

  @Override
  public FilterRange convert(String source) {
    return FilterRange.valueOf(source);
  }
}
