package com.wj.auth.annotation;

import com.wj.auth.core.security.configuration.Logical;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author weijie
 * @since 2020/9/10
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {

  /**
   * 权限
   */
  String[] value();

  /**
   * 多权限检查逻辑
   */
  Logical logical() default Logical.AND;
}
