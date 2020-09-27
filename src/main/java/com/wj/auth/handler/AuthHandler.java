package com.wj.auth.handler;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public interface AuthHandler {

  /**
   * 授权
   *
   * @return
   */
  boolean authorize(HttpServletRequest request, HttpServletResponse response, String auth,
      Set<String> userAuth);

  /**
   * 认证
   *
   * @return token
   */
  String authenticate(HttpServletRequest request, HttpServletResponse response, String header);


  /**
   * 是否解析/验证token
   *
   * @return
   */
  default boolean isDecodeToken() {
    return true;
  }

  /**
   * 是否刷新token
   *
   * @return
   */
  default boolean isRefreshToken() {
    return true;
  }
}
