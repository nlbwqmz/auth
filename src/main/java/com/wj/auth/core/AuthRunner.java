package com.wj.auth.core;

import com.wj.auth.annotation.Auth;
import com.wj.auth.annotation.FreeLogin;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * @Author: weijie
 * @Date: 2020/9/14
 */
@ConditionalOnBean(AuthManager.class)
public class AuthRunner implements ApplicationRunner {

  private final AuthManager authManager;
  private final RequestMappingHandlerMapping mapping;

  public AuthRunner(AuthManager authManager, RequestMappingHandlerMapping mapping) {
    this.authManager = authManager;
    this.mapping = mapping;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
    Map<RequestMappingInfo, String> authMap = new HashMap<>();
    Set<RequestMappingInfo> freeLoginSet = new HashSet<>();
    map.forEach((requestMappingInfo, handlerMethod) -> {
      //获取url的Set集合，一个方法可能对应多个url
      Method method = handlerMethod.getMethod();
      Auth auth = method.getAnnotation(Auth.class);
      FreeLogin freeLogin = method.getAnnotation(FreeLogin.class);
      if (auth != null) {
        authMap.put(requestMappingInfo, auth.value());
      } else if (freeLogin != null) {
        freeLoginSet.add(requestMappingInfo);
      }
    });
    authManager.setAuthMap(authMap);
    authManager.setFreeLoginSet(freeLoginSet);
  }
}
