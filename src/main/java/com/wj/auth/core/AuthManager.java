package com.wj.auth.core;

import com.wj.auth.common.AuthConfig;
import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
import com.wj.auth.handler.AnonAuthHandler;
import com.wj.auth.handler.AuthHandler;
import com.wj.auth.handler.AuthcAuthHandler;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
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
  private AuthHandler authcHandler = new AuthcAuthHandler();
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  private Set<String> anonymousPatterns = new HashSet<>();
  private AntPathMatcher antPathMatcher = new AntPathMatcher();

  /*@Value("${auth.header:Authorization}")
  private String header;
  @Value("${auth.anon:''}")
  private Set<String> anon;*/
  @Autowired
  private AuthConfig authConfig;
  @Autowired
  private TokenFactory tokenFactory;
  @Value("${server.servlet.context-path}")
  private String contextPath;

  public boolean doHandler(HttpServletRequest request,HttpServletResponse response){
    HandlerHelper handlerHelper = getAuthHandler(request);
    AuthHandler handler = handlerHelper.getHandler();
    String auth = handlerHelper.getAuth();
    String authenticate = handler.authenticate(request, response, authConfig.getHeader());
    if(handler.isDecodeToken()){
      tokenFactory.decode(authenticate);
    }
    if (handler.isRefreshToken()){
      Object subject = SubjectManager.getSubject();
      long expire = SubjectManager.getExpire();
      loginSuccess(subject, expire);
    }
    return handler.authorize(request, response, auth, doAuthorization());
  }

  public HandlerHelper getAuthHandler(HttpServletRequest request){
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for(AuthHandlerEntity authHandlerEntity:handlers){
      Set<RequestVerification> requestVerifications = authHandlerEntity.getRequestVerifications();
      for(RequestVerification requestVerification:requestVerifications){
        Set<String> patterns = Optional.ofNullable(requestVerification.getPatterns()).orElse(new HashSet<>());
        Set<String> methods = Optional.ofNullable(requestVerification.getMethods()).orElse(new HashSet<>());
        if(patterns.contains(uri) && methods.contains(method)){
          return new HandlerHelper(requestVerification.getAuth(),authHandlerEntity.getHandler());
        }
      }
    }
    return null;
  }

  /**
   * 用户授权
   *
   * @return
   */
  public abstract Set<String> doAuthorization();

  /**
   * 登录成功
   * @param obj
   * @param expire
   */
  public void loginSuccess(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(authConfig.getHeader(), tokenFactory.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", authConfig.getHeader());
  }

  public void setAnon(Set<RequestVerification> anonSet) {
    if(CollectionUtils.isNotBlank(authConfig.getAnon())){
      anonSet.add(new RequestVerification(CollectionUtils.addUrlPrefix(authConfig.getAnon(),contextPath)));
    }
    Set<String> set = addAnonPatterns();
    if(CollectionUtils.isNotBlank(set)){
      anonSet.add(new RequestVerification(CollectionUtils.addUrlPrefix(set,contextPath)));
    }
    addHandler(new AuthHandlerEntity(anonSet,new AnonAuthHandler(),1));
  }

  public Set<String> addAnonPatterns(){
    return null;
  }

  public void addHandler(AuthHandlerEntity authHandlerEntity){
    this.handlers.add(authHandlerEntity);
    this.handlers.sort(Comparator.comparingInt(AuthHandlerEntity::getOrder));
  }
  class HandlerHelper{
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
