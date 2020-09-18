package com.wj.auth.core;

import com.wj.auth.common.RequestVerification;
import com.wj.auth.exception.CertificateNotFoundException;
import com.wj.auth.exception.PermissionNotFoundException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.JacksonUtils;
import java.util.HashSet;
import java.util.Iterator;
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
  private Set<String> anonymousPatterns = new HashSet<>();
  private Set<RequestVerification> freeLoginSet = new HashSet<>();
  private Set<RequestVerification> requestVerificationSet = new HashSet<>();
  private AntPathMatcher antPathMatcher = new AntPathMatcher();

  @Value("${auth.header:Authorization}")
  private String header;
  @Value("${auth.anonymous-patterns}")
  private Set<String> anonymousPatternsProperties;
  @Autowired
  private TokenFactory tokenFactory;
  @Value("${server.servlet.context-path}")
  private String contextPath;

  @PostConstruct
  private void init(){
    setAnonymousPatterns();
  }
  /**
   * 权限验证
   *
   * @param request
   */
  public void authorityVerification(HttpServletRequest request){
    Set<String> userAuthSet = doAuthorization();
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
    }
  }

  /**
   * 凭证验证
   *
   * @param request
   * @return
   */
  public boolean authorizationVerification(HttpServletRequest request) {
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

  private void setAnonymousPatterns() {
    if(CollectionUtils.isNotBlank(anonymousPatternsProperties)){
      anonymousPatterns.addAll(CollectionUtils.addUrlPrefix(anonymousPatternsProperties,contextPath));
    }
    Set<String> set = addAnonymousPatterns();
    if(CollectionUtils.isNotBlank(set)){
      anonymousPatterns.addAll(CollectionUtils.addUrlPrefix(set,contextPath));
    }
  }

  public Set<String> addAnonymousPatterns(){
    return null;
  }
}
