package com.wj.auth.core;

import com.wj.auth.common.AuthHandlerEntity;
import com.wj.auth.common.RequestVerification;
import java.util.Set;

/**
 * @author weijie
 * @since 2020/10/9
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
  default RequestVerification addAnonPatterns() {
    return null;
  }

  /**
   * 添加 权限验证 Patterns
   *
   * @return 权限验证 Patterns 集合
   */
  default Set<RequestVerification> addAuthPatterns() {
    return null;
  }

  /**
   * 添加自定义拦截器
   * @return 自定义拦截器集合
   */
  default Set<AuthHandlerEntity> addCustomHandler(){
    return null;
  }
}
