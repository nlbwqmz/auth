package com.wj.auth.utils;

import com.google.common.collect.Sets;
import com.wj.auth.common.AuthHelper;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class MatchUtils {

  private final static AntPathMatcher antPathMatcher = new AntPathMatcher();

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

  public static boolean matcher(@NonNull AuthHelper authHelper, String uri,
      String method) {
    Set<String> patterns = Optional.ofNullable(authHelper.getPatterns()).orElse(
        Sets.newHashSet());
    Set<String> methods = Optional.ofNullable(authHelper.getMethods()).orElse(
        Sets.newHashSet());
    return matcher(patterns, uri) && (CollectionUtils.isBlank(methods) || CollectionUtils
        .containsIgnoreCase(methods, method));
  }

  public static boolean matcher(@NonNull Set<AuthHelper> set, String uri,
      String method) {
    if (CollectionUtils.isNotBlank(set)) {
      for (AuthHelper item : set) {
        if (matcher(item, uri, method)) {
          return true;
        }
      }
    }
    return false;
  }
}
