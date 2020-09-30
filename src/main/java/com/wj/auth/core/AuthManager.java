package com.wj.auth.core;

import com.wj.auth.common.AuthConfig;
import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
import com.wj.auth.exception.PermissionNotFoundException;
import com.wj.auth.handler.AnonAuthHandler;
import com.wj.auth.handler.AuthHandler;
import com.wj.auth.handler.AuthcAuthHandler;
import com.wj.auth.handler.DefaultAuthHandler;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.AntPathMatcher;

/**
 * @author weijie
 * @date 2020/9/10
 */
public abstract class AuthManager {

  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  @Autowired
  private AuthConfig authConfig;
  @Autowired
  private TokenFactory tokenFactory;
  private AntPathMatcher antPathMatcher = new AntPathMatcher();
  @Value("${server.servlet.context-path:}")
  private String contextPath;

  public boolean doHandler(HttpServletRequest request, HttpServletResponse response) {
    HandlerHelper handlerHelper = getAuthHandler(request);
    if (handlerHelper != null) {
      AuthHandler handler = handlerHelper.getHandler();
      String auth = handlerHelper.getAuth();
      String authenticate = handler.authenticate(request, response, authConfig.getHeader());
      if (handler.isDecodeToken()) {
        tokenFactory.decode(authenticate);
      }
      if (handler.isRefreshToken()) {
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        loginSuccess(subject, expire);
      }
      if (handler.authorize(request, response, auth, doAuthorization())) {
        return true;
      } else {
        throw new PermissionNotFoundException("需要【" + auth + "】权限");
      }
    } else {
      return true;
    }
  }

  public HandlerHelper getAuthHandler(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for (AuthHandlerEntity authHandlerEntity : handlers) {
      Set<RequestVerification> requestVerifications = authHandlerEntity.getRequestVerifications();
      for (RequestVerification requestVerification : requestVerifications) {
        Set<String> patterns = Optional.ofNullable(requestVerification.getPatterns())
            .orElse(new HashSet<>());
        Set<String> methods = Optional.ofNullable(requestVerification.getMethods())
            .orElse(new HashSet<>());
        if (matcher(patterns, uri) && (CollectionUtils.isBlank(methods) || methods
            .contains(method))) {
          return new HandlerHelper(requestVerification.getAuth(), authHandlerEntity.getHandler());
        }
      }
    }
    return null;
  }

  private boolean matcher(Set<String> patterns, String uri) {
    Iterator<String> iterator = patterns.iterator();
    if (iterator.hasNext()) {
      String pattern = iterator.next();
      if (antPathMatcher.match(pattern, uri)) {
        return true;
      }
    }
    return false;
  }

  /**
   * 用户授权
   *
   * @return
   */
  public abstract Set<String> doAuthorization();

  /**
   * 登录成功
   *
   * @param obj
   * @param expire
   */
  public void loginSuccess(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(authConfig.getHeader(),
        tokenFactory.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", authConfig.getHeader());
  }

  public void setDefault(Set<RequestVerification> defaultSet) {
    addHandler(new AuthHandlerEntity(defaultSet, new DefaultAuthHandler(), 0));
  }

  public void setAnon(Set<RequestVerification> anonSet) {
    if (CollectionUtils.isNotBlank(authConfig.getAnon())) {
      anonSet.add(
          new RequestVerification(CollectionUtils.addUrlPrefix(authConfig.getAnon(), contextPath)));
    }
    Set<String> set = addAnonPatterns();
    if (CollectionUtils.isNotBlank(set)) {
      anonSet.add(new RequestVerification(CollectionUtils.addUrlPrefix(set, contextPath)));
    }
    addHandler(new AuthHandlerEntity(anonSet, new AnonAuthHandler(), 1));
  }

  public void setAuthc(Set<RequestVerification> authcSet) {
    addHandler(new AuthHandlerEntity(authcSet, new AuthcAuthHandler(), 2));
  }

  public Set<String> addAnonPatterns() {
    return null;
  }

  public void addHandler(AuthHandlerEntity authHandlerEntity) {
    this.handlers.add(authHandlerEntity);
    this.handlers.sort(Comparator.comparingInt(AuthHandlerEntity::getOrder));
  }

  class HandlerHelper {

    private String auth;
    private AuthHandler handler;

    public HandlerHelper() {
    }

    public HandlerHelper(String auth, AuthHandler handler) {
      this.auth = auth;
      this.handler = handler;
    }

    public String getAuth() {
      return auth;
    }

    public void setAuth(String auth) {
      this.auth = auth;
    }

    public AuthHandler getHandler() {
      return handler;
    }

    public void setHandler(AuthHandler handler) {
      this.handler = handler;
    }
  }
}
