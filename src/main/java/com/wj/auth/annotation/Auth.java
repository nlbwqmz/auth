package com.wj.auth.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.lang.NonNull;

/**
 * @author weijie
 * @since 2020/9/10
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {

  /**
   * 权限
   * @return
   */
  @NonNull String value();
}
