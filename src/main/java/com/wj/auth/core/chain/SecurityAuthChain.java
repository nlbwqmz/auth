package com.wj.auth.core.chain;

import com.wj.auth.common.AuthHelper;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.SecurityConfiguration;
import com.wj.auth.core.AuthLogin;
import com.wj.auth.core.AuthRealm;
import com.wj.auth.core.security.AuthTokenGenerate;
import com.wj.auth.core.security.configuration.AuthHandlerEntity;
import com.wj.auth.core.security.configuration.Logical;
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
 * @author 魏杰
 * @since 0.0.2
 */
@Order(1)
@Component
public class SecurityAuthChain implements AuthChain {

  private final SecurityConfiguration securityConfiguration;
  private final AuthTokenGenerate authTokenGenerate;
  private final AuthRealm authRealm;
  private final AuthLogin authLogin;
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public SecurityAuthChain(AuthAutoConfiguration authAutoConfiguration,
      AuthTokenGenerate authTokenGenerate,
      AuthRealm authRealm,
      AuthLogin authLogin) {
    this.securityConfiguration = authAutoConfiguration.getSecurity();
    this.authTokenGenerate = authTokenGenerate;
    this.authRealm = authRealm;
    this.authLogin = authLogin;
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
          .authenticate(request, response, securityConfiguration.getHeader());
      if (handler.isDecodeToken()) {
        authTokenGenerate.decode(authenticate);
      }
      if (handler.isRefreshToken()) {
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        authLogin.doLogin(subject, expire);
      }
      if (handler.isAuthorize() && !handler
          .authorize(request, response, auth, handlerHelper.getLogical(),
              authRealm.doAuthorization())) {
        throw new PermissionNotFoundException(
            String.format("%s permission required, logical is %s.", ArrayUtils.format(auth),
                handlerHelper.getLogical().name()));
      }
    }
    chain.doAuth();
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  private HandlerHelper getAuthHandler(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for (AuthHandlerEntity authHandlerEntity : handlers) {
      Set<AuthHelper> authHelpers = authHandlerEntity.getAuthHelpers();
      for (AuthHelper authHelper : authHelpers) {
        if (MatchUtils.matcher(authHelper, uri, method)) {
          return new HandlerHelper(authHelper.getAuth(), authHelper.getLogical(),
              authHandlerEntity.getHandler());
        }
      }
    }
    if (securityConfiguration.isStrict()) {
      return new HandlerHelper(new AuthcInterceptorHandler());
    } else {
      return null;
    }
  }

  public void setAuth(Set<AuthHelper> authSet) {
    Set<AuthHelper> authHelperSet = authRealm.addAuthPatterns();
    if (CollectionUtils.isNotBlank(authHelperSet)) {
      for (AuthHelper authHelper : authHelperSet) {
        Set<String> patterns = authHelper.getPatterns();
        String[] auth = authHelper.getAuth();
        if (CollectionUtils.isNotBlank(patterns) && ArrayUtils.isAllNotBlank(auth)) {
          authHelper.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
          authSet.add(authHelper);
        } else {
          String clazz = authRealm.getClass().toString();
          clazz = clazz.substring(6, clazz.indexOf("$$"));
          throw new AuthInitException(
              String
                  .format("at %s.addAuthPatterns, neither patterns nor auth can be blank.", clazz));
        }
      }
    }
    addHandler(new AuthHandlerEntity(authSet, new AuthInterceptorHandler(), 0));
  }

  public void setAnon(Set<AuthHelper> anonSet) {
    if (CollectionUtils.isNotBlank(securityConfiguration.getAnon())) {
      anonSet.add(AuthHelper.otherBuilder()
          .setPatterns(CollectionUtils.addUrlPrefix(securityConfiguration.getAnon(), contextPath))
          .build());
    }
    Set<AuthHelper> anonAuthHelperSet = authRealm.addAnonPatterns();
    if (CollectionUtils.isNotBlank(anonAuthHelperSet)) {
      for (AuthHelper authHelper : anonAuthHelperSet) {
        if (authHelper != null) {
          Set<String> patterns = authHelper.getPatterns();
          if (CollectionUtils.isNotBlank(patterns)) {
            authHelper.setPatterns(CollectionUtils.addUrlPrefix(patterns, contextPath));
            anonSet.add(authHelper);
          } else {
            String clazz = authRealm.getClass().toString();
            clazz = clazz.substring(6, clazz.indexOf("$$"));
            throw new AuthInitException(
                String.format("at %s.addAnonPatterns, patterns can't be blank.", clazz));
          }
        }
      }
    }
    addHandler(new AuthHandlerEntity(anonSet, new AnonInterceptorHandler(), 100));
  }

  public void setAuthc(Set<AuthHelper> authcSet) {
    addHandler(new AuthHandlerEntity(authcSet, new AuthcInterceptorHandler(), 200));
  }

  public void setCustomHandler() {
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
