package com.wj.auth.exception;

/**
 * @author weijie
 * @date: 2020/9/30
 */
public class AuthException extends RuntimeException{
  public AuthException() {
    super();
  }
  public AuthException(String msg){
    super(msg);
  }

}
