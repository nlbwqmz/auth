package com.wj.auth.core;

import com.wj.auth.annotation.Anon;
import com.wj.auth.annotation.Auth;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.core.chain.SecurityChain;
import com.wj.auth.core.security.AuthRealm;
import com.wj.auth.core.security.configuration.RequestVerification;
import com.wj.auth.core.security.configuration.SecurityConfiguration;
import com.wj.auth.exception.AuthInitException;
import com.wj.auth.utils.ArrayUtils;
import com.wj.auth.utils.CollectionUtils;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * @author weijie
 * @since 2020/9/14
 */
@ConditionalOnBean(AuthRealm.class)
@ServletComponentScan("com.wj.auth")
@ComponentScan("com.wj.auth")
public class Run implements ApplicationRunner {

  private final RequestMappingHandlerMapping mapping;
  private final SecurityConfiguration security;
  private final SecurityChain securityChain;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public Run(RequestMappingHandlerMapping mapping,
      AuthAutoConfiguration authAutoConfiguration,
      SecurityChain securityChain) {
    this.mapping = mapping;
    this.security = authAutoConfiguration.getSecurity();
    this.securityChain = securityChain;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
    Set<RequestVerification> authSet = new HashSet<>();
    Set<RequestVerification> anonSet = new HashSet<>();
    Set<RequestVerification> authcSet = new HashSet<>();
    map.forEach((requestMappingInfo, handlerMethod) -> {
      Method method = handlerMethod.getMethod();
      Set<RequestMethod> methods = requestMappingInfo.getMethodsCondition().getMethods();
      Set<String> methodResult = new HashSet<>();
      Set<String> patternResult;
      Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
      if (CollectionUtils.isNotBlank(methods)) {
        methods.forEach(item -> methodResult.add(item.name()));
      }
      patternResult = CollectionUtils.addUrlPrefix(patterns, contextPath);
      if (security.isAnnotationEnabled()) {
        Auth auth = method.getAnnotation(Auth.class);
        Anon anon = method.getAnnotation(Anon.class);
        Class<?> declaringClass = method.getDeclaringClass();
        if (auth != null) {
          String[] authValueArray = auth.value();
          if (ArrayUtils.isAllNotBlank(authValueArray)) {
            authSet.add(
                RequestVerification.build()
                    .setPatterns(patternResult)
                    .setMethods(methodResult)
                    .setAuth(auth.value())
                    .setLogical(auth.logical()));
          } else {
            throw new AuthInitException(
                String.format("at %s.%s, annotation Auth value can't be blank",
                    declaringClass.toString().substring(6), method.getName()));
          }
          return;
        } else if (anon != null) {
          anonSet
              .add(RequestVerification.build().setPatterns(patternResult).setMethods(methodResult));
          return;
        }
        Auth declaredAuth = declaringClass.getAnnotation(Auth.class);
        Anon declaredAnon = declaringClass.getAnnotation(Anon.class);
        if (declaredAuth != null) {
          authSet.add(RequestVerification.build()
              .setPatterns(patternResult)
              .setMethods(methodResult)
              .setAuth(declaredAuth.value())
              .setLogical(declaredAuth.logical()));
          return;
        } else if (declaredAnon != null) {
          anonSet
              .add(RequestVerification.build().setPatterns(patternResult).setMethods(methodResult));
          return;
        }
      }
      authcSet.add(RequestVerification.build().setPatterns(patternResult).setMethods(methodResult));
    });
    securityChain.setAuth(authSet);
    securityChain.setAnon(anonSet);
    securityChain.setAuthc(authcSet);
    securityChain.setCustomHandler();
  }
}
