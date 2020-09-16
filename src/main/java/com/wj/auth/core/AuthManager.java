package com.wj.auth.core;

import com.wj.auth.exception.CertificateNotFoundException;
import com.wj.auth.exception.PermissionNotFoundException;
import com.wj.auth.utils.JacksonUtils;
import com.wj.auth.utils.TokenFactory;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

/**
 * @Author: weijie
 * @Date: 2020/9/10
 */
public abstract class AuthManager {

  private Map<RequestMappingInfo, String> authMap = new HashMap<>();
  private Set<RequestMappingInfo> freeLoginSet = new HashSet<>();
  private AntPathMatcher antPathMatcher = new AntPathMatcher();
  @Value("${auth.header:Authorization}")
  private String header;
  @Autowired
  private TokenFactory tokenFactory;

  /**
   * 权限验证
   *
   * @param request
   */
  public void authorityVerification(HttpServletRequest request) {
    Set<String> userAuthSet = doAuthorization();
    String uri = request.getRequestURI();
    String method = request.getMethod();
    for (RequestMappingInfo requestMappingInfo : authMap.keySet()) {
      Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
      Set<RequestMethod> requestMethods = requestMappingInfo.getMethodsCondition().getMethods();
      if (checkPatterns(uri, patterns) && checkRequestMethod(method, requestMethods)) {
        if (userAuthSet == null || userAuthSet.isEmpty() || !userAuthSet
            .contains(authMap.get(requestMappingInfo))) {
          throw new PermissionNotFoundException("没有权限：" + authMap.get(requestMappingInfo));
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

  /**
   * 是否为免登录接口
   *
   * @param request
   * @return
   */
  private boolean isFreeLogin(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String method = request.getMethod();
    Iterator<RequestMappingInfo> iterator = freeLoginSet.iterator();
    while (iterator.hasNext()) {
      RequestMappingInfo requestMappingInfo = iterator.next();
      Set<String> patterns = requestMappingInfo.getPatternsCondition().getPatterns();
      Set<RequestMethod> requestMethods = requestMappingInfo.getMethodsCondition().getMethods();
      if (checkPatterns(uri, patterns) && checkRequestMethod(method, requestMethods)) {
        return true;
      }
    }
    return false;
  }

  /**
   * 验证请求方法
   *
   * @param method
   * @param requestMethods
   * @return
   */
  private boolean checkRequestMethod(String method, Set<RequestMethod> requestMethods) {
    if (isBlankSet(requestMethods)) {
      return true;
    }
    Iterator<RequestMethod> iterator = requestMethods.iterator();
    while (iterator.hasNext()) {
      if (iterator.next().name().equals(method)) {
        return true;
      }
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
   * 设置url权限
   * @param authMap
   */
  public void setAuthMap(
      Map<RequestMappingInfo, String> authMap) {
    this.authMap = authMap;
  }

  /**
   * 设置免登录url
   * @param freeLoginSet
   */
  public void setFreeLoginSet(
      Set<RequestMappingInfo> freeLoginSet) {
    this.freeLoginSet = freeLoginSet;
  }

  /**
   * set是否为空
   * @param set
   * @return
   */
  public boolean isBlankSet(Set set) {
    return set == null || set.isEmpty();
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
}
