package com.wj.auth.utils;

import com.google.common.collect.Sets;
import com.wj.auth.core.security.configuration.RequestVerification;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import org.springframework.lang.NonNull;
import org.springframework.util.AntPathMatcher;

/**
 * @author weijie
 * @since 2020/10/19
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

  public static boolean matcher(@NonNull RequestVerification requestVerification, String uri,
      String method) {
    Set<String> patterns = Optional.ofNullable(requestVerification.getPatterns()).orElse(
        Sets.newHashSet());
    Set<String> methods = Optional.ofNullable(requestVerification.getMethods()).orElse(
        Sets.newHashSet());
    return matcher(patterns, uri) && (CollectionUtils.isBlank(methods) || CollectionUtils.containsIgnoreCase(methods, method));
  }

  public static boolean matcher(@NonNull Set<RequestVerification> set, String uri,
      String method) {
    if(CollectionUtils.isNotBlank(set)){
      for(RequestVerification item:set){
        if(matcher(item, uri, method)){
          return true;
        }
      }
    }
    return false;
  }
}
