package com.wj.auth.core.security;

import com.google.common.base.Strings;
import com.wj.auth.annotation.Anon;
import com.wj.auth.annotation.Auth;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.ErrorController;
import com.wj.auth.core.security.entity.RequestVerification;
import com.wj.auth.exception.AuthException;
import com.wj.auth.utils.CollectionUtils;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * @author weijie
 * @since 2020/9/14
 */
@ConditionalOnBean(AuthRealm.class)
@Import({AuthManager.class, AuthTokenGenerate.class, ErrorController.class})
@ServletComponentScan("com.wj.auth.core")
public class AuthRunner implements ApplicationRunner {

  private final AuthManager authManager;
  private final RequestMappingHandlerMapping mapping;
  private final AuthAutoConfiguration authAutoConfiguration;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public AuthRunner(@Autowired(required = false) AuthManager authManager,
      RequestMappingHandlerMapping mapping,
      AuthAutoConfiguration authAutoConfiguration) {
    this.authManager = authManager;
    this.mapping = mapping;
    this.authAutoConfiguration = authAutoConfiguration;
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
      if (authAutoConfiguration.isAnnotationEnabled()) {
        Auth auth = method.getAnnotation(Auth.class);
        Anon anon = method.getAnnotation(Anon.class);
        if (auth != null) {
          if (!Strings.isNullOrEmpty(auth.value())) {
            authSet.add(new RequestVerification(patternResult, methodResult, auth.value()));
          } else {
            throw new AuthException(String.format("at %s.%s, annotation Auth value can't be blank",
                method.getDeclaringClass().toString(), method.getName()));
          }
          return;
        }
        if (anon != null) {
          anonSet.add(new RequestVerification(patternResult, methodResult));
          return;
        }
      }
      authcSet.add(new RequestVerification(patternResult, methodResult));
    });
    authManager.setAuth(authSet);
    authManager.setAnon(anonSet);
    authManager.setAuthc(authcSet);
    authManager.setCustomHandler();
  }
}
