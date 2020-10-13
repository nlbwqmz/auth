package com.wj.auth.core;

import com.wj.auth.common.AuthConfiguration;
import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
import com.wj.auth.exception.AuthException;
import com.wj.auth.exception.PermissionNotFoundException;
import com.wj.auth.handler.AnonInterceptorHandler;
import com.wj.auth.handler.AuthInterceptorHandler;
import com.wj.auth.handler.AuthcInterceptorHandler;
import com.wj.auth.handler.InterceptorHandler;
import com.wj.auth.utils.AuthUtils;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import com.wj.auth.utils.StringUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;

/**
 * @author weijie
 * @since 2020/9/10
 */
@ConditionalOnBean(AuthRealm.class)
public class AuthManager {

  private final AuthConfiguration authConfiguration;
  private final TokenFactory tokenFactory;
  private final AuthRealm authRealm;
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  @Value("${server.servlet.context-path:}")
  private String contextPath;
  private Set<String> exclusions;

//  public void xss(HttpServletRequest request, HttpServletResponse response) {
//    if (exclusions == null) {
//      Set<String> config = Optional.ofNullable(authConfiguration.getXss().getExclusions())
//          .orElse(Sets.newHashSet());
//      if (!Strings.isNullOrEmpty(contextPath)) {
//        exclusions = CollectionUtils.addUrlPrefix(config, contextPath);
//      } else {
//        exclusions = config;
//      }
//    }
//    String uri = request.getRequestURI();
//    if (AuthUtils.matcher(exclusions, uri)) {
//
//      chain.doFilter(new XssAndSqlHttpServletRequestWrapper(req), response);
//    } else {
//      chain.doFilter(request, response);
//    }
//  }

  public AuthManager(AuthConfiguration authConfiguration, TokenFactory tokenFactory,
      AuthRealm authRealm) {
    this.authConfiguration = authConfiguration;
    this.tokenFactory = tokenFactory;
    this.authRealm = authRealm;
  }

  protected boolean doHandler(HttpServletRequest request, HttpServletResponse response) {
    HandlerHelper handlerHelper = getAuthHandler(request);
    if (handlerHelper != null) {
      InterceptorHandler handler = handlerHelper.getHandler();
      String auth = handlerHelper.getAuth();
      String authenticate = handler.authenticate(request, response, authConfiguration.getHeader());
      if (handler.isDecodeToken()) {
        tokenFactory.decode(authenticate);
      }
      if (handler.isRefreshToken()) {
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        loginSuccess(subject, expire);
      }
      if (handler.authorize(request, response, auth, authRealm.doAuthorization())) {
        return true;
      } else {
        throw new PermissionNotFoundException(String.format("%s permission required", auth));
      }
    } else {
      return true;
    }
  }

  private HandlerHelper getAuthHandler(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for (AuthHandlerEntity authHandlerEntity : handlers) {
      Set<RequestVerification> requestVerifications = authHandlerEntity.getRequestVerifications();
      for (RequestVerification requestVerification : requestVerifications) {
        Set<String> patterns = Optional.ofNullable(requestVerification.getPatterns())
            .orElse(new HashSet<>());
        Set<String> methods = Optional.ofNullable(requestVerification.getMethods())
            .orElse(new HashSet<>());
        if (AuthUtils.matcher(patterns, uri) && (CollectionUtils.isBlank(methods) || CollectionUtils
            .containsIgnoreCase(methods, method))) {
          return new HandlerHelper(requestVerification.getAuth(), authHandlerEntity.getHandler());
        }
      }
    }
    return null;
  }


  /**
   * 登录成功
   *
   * @param obj
   * @param expire
   */
  public void loginSuccess(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(authConfiguration.getHeader(),
        tokenFactory.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", authConfiguration.getHeader());
  }

  protected void setAuth(Set<RequestVerification> authSet) {

    Set<RequestVerification> requestVerificationSet = authRealm.addAuthPatterns();
    if (CollectionUtils.isNotBlank(requestVerificationSet)) {
      for (RequestVerification requestVerification : requestVerificationSet) {
        Set<String> patterns = requestVerification.getPatterns();
        String auth = requestVerification.getAuth();
        if (CollectionUtils.isNotBlank(patterns) && StringUtils.isNotBlank(auth)) {
          requestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
          authSet.add(requestVerification);
        } else {
          String clazz = authRealm.getClass().toString();
          clazz = clazz.substring(0, clazz.indexOf("$$"));
          throw new AuthException(
              String
                  .format("at %s@addAuthPatterns, neither patterns nor auth can be blank.", clazz));
        }
      }
    }
    addHandler(new AuthHandlerEntity(authSet, new AuthInterceptorHandler(), 0));
  }

  protected void setAnon(Set<RequestVerification> anonSet) {
    if (CollectionUtils.isNotBlank(authConfiguration.getAnon())) {
      anonSet.add(
          new RequestVerification(
              CollectionUtils.addUrlPrefix(authConfiguration.getAnon(), contextPath)));
    }
    RequestVerification anonRequestVerification = authRealm.addAnonPatterns();
    if (anonRequestVerification != null) {
      Set<String> patterns = anonRequestVerification.getPatterns();
      if (CollectionUtils.isNotBlank(patterns)) {
        anonRequestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
        anonSet.add(anonRequestVerification);
      } else {
        String clazz = authRealm.getClass().toString();
        clazz = clazz.substring(0, clazz.indexOf("$$"));
        throw new AuthException(
            String.format("at %s@addAnonPatterns, patterns can't be blank.", clazz));
      }
    }
    addHandler(new AuthHandlerEntity(anonSet, new AnonInterceptorHandler(), 100));
  }

  protected void setAuthc(Set<RequestVerification> authcSet) {
    addHandler(new AuthHandlerEntity(authcSet, new AuthcInterceptorHandler(), 200));
  }

  protected void setCustomHandler() {
    Set<AuthHandlerEntity> customHandler = authRealm.addCustomHandler();
    if (CollectionUtils.isNotBlank(customHandler)) {
      for (AuthHandlerEntity authHandlerEntity : customHandler) {
        addHandler(authHandlerEntity);
      }
    }
    this.handlers.sort(Comparator.comparingInt(AuthHandlerEntity::getOrder));
  }

  private void addHandler(AuthHandlerEntity authHandlerEntity) {
    this.handlers.add(authHandlerEntity);
  }

  private static class HandlerHelper {

    private String auth;
    private InterceptorHandler handler;

    public HandlerHelper(String auth, InterceptorHandler handler) {
      this.auth = auth;
      this.handler = handler;
    }

    public String getAuth() {
      return auth;
    }

    public void setAuth(String auth) {
      this.auth = auth;
    }

    public InterceptorHandler getHandler() {
      return handler;
    }

    public void setHandler(InterceptorHandler handler) {
      this.handler = handler;
    }
  }
}
