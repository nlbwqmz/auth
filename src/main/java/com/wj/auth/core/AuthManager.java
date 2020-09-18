package com.wj.auth.core;

import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
import com.wj.auth.exception.CertificateNotFoundException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.AntPathMatcher;

/**
 * @Author: weijie
 * @Date: 2020/9/10
 */
public abstract class AuthManager {
  private List<AuthHandlerEntity> handlers = new ArrayList<>();
  private Set<String> anonymousPatterns = new HashSet<>();
  private Set<RequestVerification> freeLoginSet = new HashSet<>();
  private Set<RequestVerification> requestVerificationSet = new HashSet<>();
  private AntPathMatcher antPathMatcher = new AntPathMatcher();

  @Value("${auth.header:Authorization}")
  private String header;
  @Value("${auth.anon}")
  private Set<String> anon;
  @Autowired
  private TokenFactory tokenFactory;
  @Value("${server.servlet.context-path}")
  private String contextPath;

  public boolean doHandler(HttpServletRequest request,HttpServletResponse response){
    AuthHandler handler = getAuthHandler(request, response);
    boolean authenticate = handler.authorityVerification(request, response);
    boolean authorize = handler.authorizationVerification(request, response);
    return false;
  }

  public AuthHandler getAuthHandler(HttpServletRequest request,HttpServletResponse response){
    return null;
  }
  /**
   * 权限验证
   *
   * @param request
   */
  public boolean authorityVerification(HttpServletRequest request,HttpServletResponse response){

    return false;
    /*Set<String> userAuthSet = doAuthorization();
    String uri = request.getRequestURI();
    String method = request.getMethod();
    Iterator<RequestVerification> iterator = requestVerificationSet.iterator();
    while (iterator.hasNext()){
      RequestVerification next = iterator.next();
      Set<String> patterns = next.getPatterns();
      Set<String> methods = next.getMethods();
      String auth = next.getAuth();
      if (checkPatterns(uri, patterns) && checkRequestMethod(method, methods)) {
          if(CollectionUtils.isBlank(userAuthSet) || !userAuthSet.contains(auth)){
            throw new PermissionNotFoundException("Not Found Permission:" + auth);
          }
        }
    }*/
  }

  /**
   * 凭证验证
   *
   * @param request
   * @return
   */
  public boolean authorizationVerification(HttpServletRequest request,HttpServletResponse response) {
    if (isFreeLogin(request)) {
      return true;
    } else {
      String authorization = request.getHeader(header);
      if (authorization != null && authorization.trim().length() > 0) {
        tokenFactory.decode(authorization);
        Object subject = SubjectManager.getSubject();
        long expire = SubjectManager.getExpire();
        loginSuccess(subject, expire);
      } else {
        throw new CertificateNotFoundException();
      }
    }
    return true;
  }

  public boolean isAnonymous(HttpServletRequest request){
    for(String pattern:anonymousPatterns){
      if(antPathMatcher.match(pattern,request.getRequestURI())){
        return true;
      }
    }
    return false;
  }

  /**
   * 是否为免登录接口
   *
   * @param request
   * @return
   */
  private boolean isFreeLogin(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    Iterator<RequestVerification> iterator = freeLoginSet.iterator();
    while (iterator.hasNext()) {
      RequestVerification requestVerification = iterator.next();
      Set<String> patterns = requestVerification.getPatterns();
      Set<String> methods = requestVerification.getMethods();
      if (checkPatterns(uri, patterns) && checkRequestMethod(method, methods)) {
        return true;
      }
    }
    return false;
  }

  /**
   * 验证请求方法
   *
   * @param method
   * @param methods
   * @return
   */
  private boolean checkRequestMethod(String method, Set<String> methods) {
    if (CollectionUtils.isBlank(methods) || methods.contains(method)) {
      return true;
    }
    return false;
  }

  /**
   * 验证路由
   *
   * @param uri
   * @param patterns
   * @return
   */
  private boolean checkPatterns(String uri, Set<String> patterns) {
    Iterator<String> iterator = patterns.iterator();
    while (iterator.hasNext()) {
      if (antPathMatcher.match(iterator.next(), uri)) {
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
   * 设置免登录url
   * @param freeLoginSet
   */
  public void setFreeLoginSet(
      Set<RequestVerification> freeLoginSet) {
    this.freeLoginSet = freeLoginSet;
  }

  /**
   * 登录成功
   * @param obj
   * @param expire
   */
  public void loginSuccess(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(header, tokenFactory.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", header);
  }

  public void setRequestVerificationSet(
      Set<RequestVerification> requestVerificationSet) {
    this.requestVerificationSet = requestVerificationSet;
  }

  public void setAnon(Set<RequestVerification> anonSet) {
    if(CollectionUtils.isNotBlank(anon)){
      anonSet.add(new RequestVerification(CollectionUtils.addUrlPrefix(anon,contextPath)));
    }
    Set<String> set = addAnonymousPatterns();
    if(CollectionUtils.isNotBlank(set)){
      anonSet.add(new RequestVerification(CollectionUtils.addUrlPrefix(set,contextPath)));
    }
    addHandler(new AuthHandlerEntity(anonSet,new FreeLoginAuthHandler(),1));
  }

  public Set<String> addAnonymousPatterns(){
    return null;
  }

  public void addHandler(AuthHandlerEntity authHandlerEntity){
    this.handlers.add(authHandlerEntity);
    this.handlers.sort(Comparator.comparingInt(AuthHandlerEntity::getOrder));
  }
}
