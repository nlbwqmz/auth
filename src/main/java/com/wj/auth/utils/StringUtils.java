package com.wj.auth.utils;

/**
 * @Author: weijie
 * @Date: 2020/9/18
 */
public class StringUtils {
  public static boolean isNotBlank(String str){
    return str != null && str.trim().length() > 0;
  }

  public static boolean isBlank(String str){
    return str == null || str.trim().length() == 0;
  }
}
