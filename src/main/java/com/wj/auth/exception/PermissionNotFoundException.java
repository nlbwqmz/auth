package com.wj.auth.exception;

/**
 * 权限未找到异常
 * @author weijie
 * @date 2020/9/11
 */
public class PermissionNotFoundException extends AuthException{
  public PermissionNotFoundException(String message) {
    super(message);
  }
}
