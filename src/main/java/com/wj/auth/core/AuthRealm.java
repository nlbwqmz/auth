package com.wj.auth.core;

import com.wj.auth.common.AuthHelper;
import com.wj.auth.core.security.configuration.AuthHandlerEntity;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author 魏杰
 * @since 0.0.2
 */
public interface AuthRealm {

  /**
   * 用户授权
   *
   * @return 权限集合
   */
  Set<String> doAuthorization();

  /**
   * 添加 免登录 Patterns
   *
   * @return 免登录 Patterns 集合
   */
  default Set<AuthHelper> addAnonPatterns() {
    return null;
  }

  /**
   * 添加 权限验证 Patterns
   *
   * @return 权限验证 Patterns 集合
   */
  default Set<AuthHelper> addAuthPatterns() {
    return null;
  }

  /**
   * 添加自定义拦截器
   *
   * @return 自定义拦截器集合
   */
  default Set<AuthHandlerEntity> addCustomHandler() {
    return null;
  }

  /**
   * 异常处理器
   *
   * @param request
   * @param response
   * @param e
   */
  void handleException(HttpServletRequest request, HttpServletResponse response, Exception e);
}
