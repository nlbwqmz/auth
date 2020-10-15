package com.wj.auth.core.security;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.Cors;
import com.wj.auth.common.Logical;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.security.entity.AuthHandlerEntity;
import com.wj.auth.core.security.entity.RequestVerification;
import com.wj.auth.core.security.handler.AnonInterceptorHandler;
import com.wj.auth.core.security.handler.AuthInterceptorHandler;
import com.wj.auth.core.security.handler.AuthcInterceptorHandler;
import com.wj.auth.core.security.handler.InterceptorHandler;
import com.wj.auth.core.xss.XssRequestWrapper;
import com.wj.auth.exception.AuthException;
import com.wj.auth.exception.PermissionNotFoundException;
import com.wj.auth.utils.ArrayUtils;
import com.wj.auth.utils.AuthUtils;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
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

  private final AuthAutoConfiguration authAutoConfiguration;
  private final AuthTokenGenerate authTokenGenerate;
  private final AuthRealm authRealm;
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  private Set<String> xssExclusions;
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public AuthManager(AuthAutoConfiguration authAutoConfiguration,
      AuthTokenGenerate authTokenGenerate,
      AuthRealm authRealm) {
    this.authAutoConfiguration = authAutoConfiguration;
    this.authTokenGenerate = authTokenGenerate;
    this.authRealm = authRealm;
  }

  public void doAuth(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    doCors(response);
    SubjectManager.setRequest(request);
    SubjectManager.setResponse(response);
    if (doHandler(request, response)) {
      chain.doFilter(doXss(request), response);
    } else {
      throw new AuthException("Unknown exception");
    }
  }

  private boolean doHandler(HttpServletRequest request, HttpServletResponse response) {
    HandlerHelper handlerHelper = getAuthHandler(request);
    if (handlerHelper != null) {
      InterceptorHandler handler = handlerHelper.getHandler();
      String[] auth = handlerHelper.getAuth();
      String authenticate = handler
          .authenticate(request, response, authAutoConfiguration.getHeader());
      if (handler.isDecodeToken()) {
        authTokenGenerate.decode(authenticate);
      }
      if (handler.isRefreshToken()) {
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        loginSuccess(subject, expire);
      }
      if (handler.authorize(request, response, auth, handlerHelper.getLogical(),
          authRealm.doAuthorization())) {
        return true;
      } else {
        throw new PermissionNotFoundException(
            String.format("%s permission required, logical is %s.", ArrayUtils.format(auth),
                handlerHelper.getLogical().name()));
      }
    } else {
      return true;
    }
  }

  private ServletRequest doXss(HttpServletRequest request) {
    if (authAutoConfiguration.getXss().isQueryEnable()) {
      if (xssExclusions == null) {
        Set<String> config = Optional.ofNullable(authAutoConfiguration.getXss().getExclusions())
            .orElse(Sets.newHashSet());
        if (!Strings.isNullOrEmpty(contextPath)) {
          xssExclusions = CollectionUtils.addUrlPrefix(config, contextPath);
        } else {
          xssExclusions = config;
        }
      }
      String uri = request.getRequestURI();
      if (AuthUtils.matcher(xssExclusions, uri)) {
        return request;
      } else {
        return new XssRequestWrapper(request);
      }
    } else {
      return request;
    }
  }

  private void doCors(HttpServletResponse response) {
    Cors cors = authAutoConfiguration.getCors();
    if (cors.isEnabled()) {
      response.setHeader("Access-Control-Allow-Origin", cors.getAccessControlAllowOrigin());
      response.setHeader("Access-Control-Allow-Headers", cors.getAccessControlAllowHeaders());
      response.setHeader("Access-Control-Allow-Methods", cors.getAccessControlAllowMethods());
      response.setHeader("Access-Control-Allow-Credentials",
          String.valueOf(cors.getAccessControlAllowCredentials()));
      response.setHeader("Access-Control-Max-Age", cors.getAccessControlMaxAge());
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
          return new HandlerHelper(requestVerification.getAuth(), requestVerification.getLogical(),
              authHandlerEntity.getHandler());
        }
      }
    }
    if (authAutoConfiguration.isStrict()) {
      return new HandlerHelper(new AuthcInterceptorHandler());
    } else {
      return null;
    }
  }


  /**
   * 登录成功
   *
   * @param obj
   * @param expire
   */
  public void loginSuccess(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(authAutoConfiguration.getHeader(),
        authTokenGenerate.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", authAutoConfiguration.getHeader());
  }

  protected void setAuth(Set<RequestVerification> authSet) {
    Set<RequestVerification> requestVerificationSet = authRealm.addAuthPatterns();
    if (CollectionUtils.isNotBlank(requestVerificationSet)) {
      for (RequestVerification requestVerification : requestVerificationSet) {
        Set<String> patterns = requestVerification.getPatterns();
        String[] auth = requestVerification.getAuth();
        if (CollectionUtils.isNotBlank(patterns) && ArrayUtils.isAllNotBlank(auth)) {
          requestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
          authSet.add(requestVerification);
        } else {
          String clazz = authRealm.getClass().toString();
          clazz = clazz.substring(6, clazz.indexOf("$$"));
          throw new AuthException(
              String
                  .format("at %s.addAuthPatterns, neither patterns nor auth can be blank.", clazz));
        }
      }
    }
    addHandler(new AuthHandlerEntity(authSet, new AuthInterceptorHandler(), 0));
  }

  protected void setAnon(Set<RequestVerification> anonSet) {
    if (CollectionUtils.isNotBlank(authAutoConfiguration.getAnon())) {
      anonSet.add(
          new RequestVerification(
              CollectionUtils.addUrlPrefix(authAutoConfiguration.getAnon(), contextPath)));
    }
    RequestVerification anonRequestVerification = authRealm.addAnonPatterns();
    if (anonRequestVerification != null) {
      Set<String> patterns = anonRequestVerification.getPatterns();
      if (CollectionUtils.isNotBlank(patterns)) {
        anonRequestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
        anonSet.add(anonRequestVerification);
      } else {
        String clazz = authRealm.getClass().toString();
        clazz = clazz.substring(6, clazz.indexOf("$$"));
        throw new AuthException(
            String.format("at %s.addAnonPatterns, patterns can't be blank.", clazz));
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

    private String[] auth;
    private Logical logical;
    private InterceptorHandler handler;

    public HandlerHelper(InterceptorHandler handler) {
      this.handler = handler;
    }

    public HandlerHelper(String[] auth, Logical logical, InterceptorHandler handler) {
      this.auth = auth;
      this.logical = logical;
      this.handler = handler;
    }

    public String[] getAuth() {
      return auth;
    }

    public void setAuth(String[] auth) {
      this.auth = auth;
    }

    public Logical getLogical() {
      return logical;
    }

    public void setLogical(Logical logical) {
      this.logical = logical;
    }

    public InterceptorHandler getHandler() {
      return handler;
    }

    public void setHandler(InterceptorHandler handler) {
      this.handler = handler;
    }
  }
}
