package com.wj.auth.exception;

/**
 * @author weijie
 * @date 2020/9/14
 */
public class JsonException extends RuntimeException{
  public JsonException() {
    super("JSON转换异常！");
  }
}
