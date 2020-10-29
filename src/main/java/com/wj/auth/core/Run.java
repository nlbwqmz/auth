package com.wj.auth.core;

import com.google.common.collect.Sets;
import com.wj.auth.annotation.rateLimiter.RateLimit;
import com.wj.auth.annotation.rateLimiter.RateLimitIgnored;
import com.wj.auth.annotation.security.Anon;
import com.wj.auth.annotation.security.Auth;
import com.wj.auth.annotation.xss.Xss;
import com.wj.auth.annotation.xss.XssIgnored;
import com.wj.auth.common.AuthHelper;
import com.wj.auth.common.FilterRange;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.RateLimiterConfiguration;
import com.wj.auth.configuration.SecurityConfiguration;
import com.wj.auth.configuration.XssConfiguration;
import com.wj.auth.core.chain.RateLimiterChain;
import com.wj.auth.core.chain.SecurityChain;
import com.wj.auth.core.chain.XssChain;
import com.wj.auth.core.security.SecurityRealm;
import com.wj.auth.exception.AuthInitException;
import com.wj.auth.utils.ArrayUtils;
import com.wj.auth.utils.CollectionUtils;
import java.lang.annotation.Annotation;
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
@ConditionalOnBean(SecurityRealm.class)
@ServletComponentScan("com.wj.auth")
@ComponentScan("com.wj.auth")
public class Run implements ApplicationRunner {

  private final RequestMappingHandlerMapping mapping;
  private final AuthAutoConfiguration authAutoConfiguration;
  private final SecurityChain securityChain;
  private final XssChain xssChain;
  private final RateLimiterChain rateLimiterChain;
  Set<AuthHelper> authSet = Sets.newHashSet();
  Set<AuthHelper> anonSet = Sets.newHashSet();
  Set<AuthHelper> authcSet = Sets.newHashSet();
  Set<AuthHelper> xssIgnoredSet = Sets.newHashSet();
  Set<AuthHelper> xssSet = Sets.newHashSet();
  Set<AuthHelper> rateLimiterIgnoredSet = Sets.newHashSet();
  Set<AuthHelper> rateLimiterSet = Sets.newHashSet();
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public Run(RequestMappingHandlerMapping mapping,
      AuthAutoConfiguration authAutoConfiguration,
      SecurityChain securityChain,
      XssChain xssChain,
      RateLimiterChain rateLimiterChain) {
    this.mapping = mapping;
    this.authAutoConfiguration = authAutoConfiguration;
    this.securityChain = securityChain;
    this.xssChain = xssChain;
    this.rateLimiterChain = rateLimiterChain;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
    map.forEach((requestMappingInfo, handlerMethod) -> {
      Method method = handlerMethod.getMethod();
      Set<RequestMethod> methods = requestMappingInfo.getMethodsCondition().getMethods();
      Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
      Set<String> methodResult = new HashSet<>();
      if (CollectionUtils.isNotBlank(methods)) {
        methods.forEach(item -> methodResult.add(item.name()));
      }
      Set<String> patternResult = CollectionUtils.addUrlPrefix(patterns, contextPath);
      initSecurity(method, patternResult, methodResult);
      initXss(method, patternResult, methodResult);
      initRateLimiter(method, patternResult, methodResult);
    });
    securityChain.setAuth(authSet);
    securityChain.setAnon(anonSet);
    securityChain.setAuthc(authcSet);
    securityChain.setCustomHandler();
    xssChain.setXss(xssSet, xssIgnoredSet);
    rateLimiterChain.setRateLimiter(rateLimiterSet, rateLimiterIgnoredSet);
  }

  private void initRateLimiter(Method method, Set<String> patterns, Set<String> methods) {
    RateLimiterConfiguration rateLimiterConfiguration = authAutoConfiguration.getRateLimiter();
    if (rateLimiterConfiguration.isEnabled()) {
      FilterRange defaultFilterRange = rateLimiterConfiguration.getDefaultFilterRange();
      if (defaultFilterRange == FilterRange.ALL && hasAnnotation(method, RateLimitIgnored.class)) {
        rateLimiterIgnoredSet
            .add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
      } else if (defaultFilterRange == FilterRange.NONE && hasAnnotation(method, RateLimit.class)) {
        rateLimiterSet
            .add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
      }
    }
  }

  private void initXss(Method method, Set<String> patterns, Set<String> methods) {
    XssConfiguration xssConfiguration = authAutoConfiguration.getXss();
    if (xssConfiguration.isQueryEnable() || xssConfiguration.isBodyEnable()) {
      FilterRange defaultFilterRange = xssConfiguration.getFilterRange();
      if (defaultFilterRange == FilterRange.ALL && hasAnnotation(method, XssIgnored.class)) {
        xssIgnoredSet
            .add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
      } else if (defaultFilterRange == FilterRange.NONE && hasAnnotation(method, Xss.class)) {
        xssSet.add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
      }
    }
  }

  private void initSecurity(Method method, Set<String> patterns, Set<String> methods) {
    SecurityConfiguration securityConfiguration = authAutoConfiguration.getSecurity();
    if (securityConfiguration.isAnnotationEnabled()) {
      Auth auth = method.getAnnotation(Auth.class);
      Anon anon = method.getAnnotation(Anon.class);
      Class<?> declaringClass = method.getDeclaringClass();
      if (auth != null) {
        String[] authValueArray = auth.value();
        if (ArrayUtils.isAllNotBlank(authValueArray)) {
          authSet.add(
              AuthHelper.authBuilder()
                  .setPatterns(patterns)
                  .setMethods(methods)
                  .setAuth(auth.value())
                  .setLogical(auth.logical()).build());
        } else {
          throw new AuthInitException(
              String.format("at %s.%s, annotation Auth value can't be blank",
                  declaringClass.toString().substring(6), method.getName()));
        }
        return;
      } else if (anon != null) {
        anonSet
            .add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
        return;
      }
      Auth declaredAuth = declaringClass.getAnnotation(Auth.class);
      Anon declaredAnon = declaringClass.getAnnotation(Anon.class);
      if (declaredAuth != null) {
        authSet.add(AuthHelper.authBuilder()
            .setPatterns(patterns)
            .setMethods(methods)
            .setAuth(declaredAuth.value())
            .setLogical(declaredAuth.logical()).build());
        return;
      } else if (declaredAnon != null) {
        anonSet
            .add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
        return;
      }
    }
    authcSet.add(AuthHelper.otherBuilder().setPatterns(patterns).setMethods(methods).build());
  }

  private boolean hasAnnotation(Method method, Class<? extends Annotation> annotationClass) {
    return method.isAnnotationPresent(annotationClass)
        || method.getDeclaringClass().isAnnotationPresent(annotationClass);
  }
}
