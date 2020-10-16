package com.wj.auth.utils;

import java.util.Iterator;
import java.util.Set;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;

/**
 * @Author: 魏杰
 * @Date: 2020/10/13
 * @Description:
 */
public class AuthUtils {

  private static AntPathMatcher antPathMatcher = new AntPathMatcher();

  public static boolean matcher(@NonNull Set<String> patterns, String uri) {
    Iterator<String> iterator = patterns.iterator();
    while (iterator.hasNext()) {
      String pattern = iterator.next();
      if (antPathMatcher.match(pattern, uri)) {
        return true;
      }
    }
    return false;
  }

}
