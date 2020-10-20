package com.wj.auth.core.chain;

import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.SecurityConfiguration;
import com.wj.auth.core.Login;
import com.wj.auth.core.security.AuthTokenGenerate;
import com.wj.auth.core.security.SecurityRealm;
import com.wj.auth.core.security.configuration.AuthHandlerEntity;
import com.wj.auth.core.security.configuration.Logical;
import com.wj.auth.core.security.configuration.RequestVerification;
import com.wj.auth.core.security.handler.AnonInterceptorHandler;
import com.wj.auth.core.security.handler.AuthInterceptorHandler;
import com.wj.auth.core.security.handler.AuthcInterceptorHandler;
import com.wj.auth.core.security.handler.InterceptorHandler;
import com.wj.auth.exception.AuthInitException;
import com.wj.auth.exception.security.PermissionNotFoundException;
import com.wj.auth.utils.ArrayUtils;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.MatchUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(0)
@Component
public class SecurityChain implements Chain {

  private final SecurityConfiguration security;
  private final AuthTokenGenerate authTokenGenerate;
  private final SecurityRealm securityRealm;
  private final Login login;
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public SecurityChain(AuthAutoConfiguration authAutoConfiguration,
      AuthTokenGenerate authTokenGenerate,
      SecurityRealm securityRealm,
      Login login) {
    this.security = authAutoConfiguration.getSecurity();
    this.authTokenGenerate = authTokenGenerate;
    this.securityRealm = securityRealm;
    this.login = login;
  }

  @Override
  public void doFilter(ChainManager chain) {
    HttpServletRequest request = SubjectManager.getRequest();
    HttpServletResponse response = SubjectManager.getResponse();
    HandlerHelper handlerHelper = getAuthHandler(request);
    if (handlerHelper != null) {
      InterceptorHandler handler = handlerHelper.getHandler();
      String[] auth = handlerHelper.getAuth();
      String authenticate = handler
          .authenticate(request, response, security.getHeader());
      if (handler.isDecodeToken()) {
        authTokenGenerate.decode(authenticate);
      }
      if (handler.isRefreshToken()) {
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        login.doLogin(subject, expire);
      }
      if (handler.isAuthorize() && !handler.authorize(request, response, auth, handlerHelper.getLogical(),
          securityRealm.doAuthorization())) {
        throw new PermissionNotFoundException(
            String.format("%s permission required, logical is %s.", ArrayUtils.format(auth),
                handlerHelper.getLogical().name()));
      }
    }
    chain.doAuth();
  }

  private HandlerHelper getAuthHandler(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for (AuthHandlerEntity authHandlerEntity : handlers) {
      Set<RequestVerification> requestVerifications = authHandlerEntity.getRequestVerifications();
      for (RequestVerification requestVerification : requestVerifications) {
        if (MatchUtils.matcher(requestVerification, uri, method)) {
          return new HandlerHelper(requestVerification.getAuth(), requestVerification.getLogical(),
              authHandlerEntity.getHandler());
        }
      }
    }
    if (security.isStrict()) {
      return new HandlerHelper(new AuthcInterceptorHandler());
    } else {
      return null;
    }
  }

  public void setAuth(Set<RequestVerification> authSet) {
    Set<RequestVerification> requestVerificationSet = securityRealm.addAuthPatterns();
    if (CollectionUtils.isNotBlank(requestVerificationSet)) {
      for (RequestVerification requestVerification : requestVerificationSet) {
        Set<String> patterns = requestVerification.getPatterns();
        String[] auth = requestVerification.getAuth();
        if (CollectionUtils.isNotBlank(patterns) && ArrayUtils.isAllNotBlank(auth)) {
          requestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
          authSet.add(requestVerification);
        } else {
          String clazz = securityRealm.getClass().toString();
          clazz = clazz.substring(6, clazz.indexOf("$$"));
          throw new AuthInitException(
              String
                  .format("at %s.addAuthPatterns, neither patterns nor auth can be blank.", clazz));
        }
      }
    }
    addHandler(new AuthHandlerEntity(authSet, new AuthInterceptorHandler(), 0));
  }

  public void setAnon(Set<RequestVerification> anonSet) {
    if (CollectionUtils.isNotBlank(security.getAnon())) {
      anonSet.add(RequestVerification.build()
          .setPatterns(CollectionUtils.addUrlPrefix(security.getAnon(), contextPath)));
    }
    RequestVerification anonRequestVerification = securityRealm.addAnonPatterns();
    if (anonRequestVerification != null) {
      Set<String> patterns = anonRequestVerification.getPatterns();
      if (CollectionUtils.isNotBlank(patterns)) {
        anonRequestVerification.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
        anonSet.add(anonRequestVerification);
      } else {
        String clazz = securityRealm.getClass().toString();
        clazz = clazz.substring(6, clazz.indexOf("$$"));
        throw new AuthInitException(
            String.format("at %s.addAnonPatterns, patterns can't be blank.", clazz));
      }
    }
    addHandler(new AuthHandlerEntity(anonSet, new AnonInterceptorHandler(), 100));
  }

  public void setAuthc(Set<RequestVerification> authcSet) {
    addHandler(new AuthHandlerEntity(authcSet, new AuthcInterceptorHandler(), 200));
  }

  public void setCustomHandler() {
    Set<AuthHandlerEntity> customHandler = securityRealm.addCustomHandler();
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
