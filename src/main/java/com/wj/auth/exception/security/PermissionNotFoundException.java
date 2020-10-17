package com.wj.auth.exception.security;

/**
 * 权限未找到异常
 *
 * @author weijie
 * @since 2020/9/11
 */
public class PermissionNotFoundException extends AuthSecurityException {

  public PermissionNotFoundException(String message) {
    super(message);
  }
}
