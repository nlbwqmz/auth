package com.wj.auth.core;

import com.wj.auth.annotation.Auth;
import com.wj.auth.annotation.FreeLogin;
import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
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
 * @Author: weijie
 * @Date: 2020/9/14
 */
@ConditionalOnBean(AuthManager.class)
public class AuthRunner implements ApplicationRunner {

  @Value("${server.servlet.context-path}")
  private String contextPath;
  private final AuthManager authManager;
  private final RequestMappingHandlerMapping mapping;

  public AuthRunner(AuthManager authManager, RequestMappingHandlerMapping mapping) {
    this.authManager = authManager;
    this.mapping = mapping;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    Set<RequestVerification> requestVerificationSet = new HashSet<>();
    Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
    Set<RequestVerification> freeLoginSet = new HashSet<>();
    map.forEach((requestMappingInfo, handlerMethod) -> {
      //获取url的Set集合，一个方法可能对应多个url
      Method method = handlerMethod.getMethod();
      Class<?> declaringClass = method.getDeclaringClass();
      Auth auth = method.getAnnotation(Auth.class);
      FreeLogin freeLogin = method.getAnnotation(FreeLogin.class);
      Set<RequestMethod> methods = requestMappingInfo.getMethodsCondition().getMethods();
      Set<String> methodResult = new HashSet<>();
      Set<String> patternResult = new HashSet<>();
      Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
      if(CollectionUtils.isNotBlank(methods)){
        methods.forEach(item -> methodResult.add(item.name()));
      }
      if(StringUtils.isNotBlank(contextPath)){
        patternResult = CollectionUtils.addUrlPrefix(patterns,contextPath);
      }
      if (auth != null) {
        requestVerificationSet.add(new RequestVerification(patternResult, methodResult,auth.value()));
      }
      if (freeLogin != null) {
        freeLoginSet.add(new RequestVerification(patternResult,methodResult));
      }
    });
    authManager.addHandler(new AuthHandlerEntity(requestVerificationSet,new DefaultAuthHandler(),0));
    authManager.setAnon(freeLoginSet);
//    authManager.addHandler(new AuthHandlerEntity(freeLoginSet,new FreeLoginAuthHandler(),1));
  }
}
