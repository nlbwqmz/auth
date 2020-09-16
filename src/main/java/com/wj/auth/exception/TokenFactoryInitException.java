package com.wj.auth.exception;

/**
 * @Author: weijie
 * @Date: 2020/9/15
 */
public class TokenFactoryInitException extends RuntimeException{

  public TokenFactoryInitException() {
    super("JwtUtil初始化错误");
  }
  public TokenFactoryInitException(String msg) {
    super(msg);
  }
}
