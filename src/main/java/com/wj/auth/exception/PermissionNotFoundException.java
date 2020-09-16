package com.wj.auth.exception;

/**
 * 权限未找到异常
 * @Author: weijie
 * @Date: 2020/9/11
 */
public class PermissionNotFoundException extends RuntimeException{
  public PermissionNotFoundException(String message) {
    super(message);
  }
}
