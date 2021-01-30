package com.wj.auth.annotation;

import com.wj.auth.configuration.AuthAutoConfiguration;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

/**
 * 启用Auth
 * @author 魏杰
 * @since 2021/1/30
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AuthAutoConfiguration.class)
public @interface EnableAuth {

}
