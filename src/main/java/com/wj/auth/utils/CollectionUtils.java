package com.wj.auth.utils;

import com.google.common.base.Strings;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author weijie
 * @since 2020/9/18
 */
public class CollectionUtils {

  /**
   * 集合是否为空
   *
   * @param collection
   * @return
   */
  public static boolean isBlank(Collection collection) {
    return collection == null || collection.isEmpty();
  }

  public static boolean isNotBlank(Collection collection) {
    return !isBlank(collection);
  }

  public static Set<String> addUrlPrefix(Set<String> set, String prefix) {
    if (Strings.isNullOrEmpty(prefix)) {
      prefix = "";
    }
    Set<String> result = new HashSet<>();
    for (String item : set) {
      if (item.startsWith("/")) {
        result.add(prefix + item);
      } else {
        result.add(prefix + "/" + item);
      }
    }
    return result;
  }

  public static boolean containsIgnoreCase(Collection<String> collection, String target) {
    if (isBlank(collection)) {
      return false;
    }
    for (String str : collection) {
      if (str.equalsIgnoreCase(target)) {
        return true;
      }
    }
    return false;
  }

}
