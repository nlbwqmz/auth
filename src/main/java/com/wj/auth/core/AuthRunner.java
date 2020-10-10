package com.wj.auth.core;

import com.wj.auth.annotation.Anon;
import com.wj.auth.annotation.Auth;
import com.wj.auth.common.AuthConfiguration;
import com.wj.auth.common.RequestVerification;
import com.wj.auth.exception.AuthException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.StringUtils;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * @author weijie
 * @since 2020/9/14
 */
@ConditionalOnBean(AuthRealm.class)
public class AuthRunner implements ApplicationRunner {

  private final AuthManager authManager;
  private final RequestMappingHandlerMapping mapping;
  private final AuthConfiguration authConfiguration;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public AuthRunner(AuthManager authManager, RequestMappingHandlerMapping mapping,
      AuthConfiguration authConfiguration) {
    this.authManager = authManager;
    this.mapping = mapping;
    this.authConfiguration = authConfiguration;
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
        if(authConfiguration.isAnnotationEnabled()){
          Auth auth = method.getAnnotation(Auth.class);
          Anon anon = method.getAnnotation(Anon.class);
          if(auth != null){
            if(StringUtils.isNotBlank(auth.value())){
              authSet.add(new RequestVerification(patternResult, methodResult, auth.value()));
            } else {
              throw new AuthException(String.format("at %s@%s, annotation Auth value can't be blank", method.getDeclaringClass().toString(), method.getName()));
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
