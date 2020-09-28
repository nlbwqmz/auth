package com.wj.auth.utils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author weijie
 * @date 2020/9/18
 */
public class CollectionUtils {
  /**
   * 集合是否为空
   * @param collection
   * @return
   */
  public static boolean isBlank(Collection collection) {
    return collection == null || collection.isEmpty();
  }

  public static boolean isNotBlank(Collection collection) {
    return !isBlank(collection);
  }

  public static Set<String> addUrlPrefix(Set<String> set,String prefix){
    if(StringUtils.isBlank(prefix)){
      prefix = "";
    }
    Set<String> result = new HashSet<>();
    for(String item:set){
      if(item.startsWith("/")){
        result.add(prefix + item);
      }else{
        result.add(prefix + "/" +item);
      }
    }
    return result;
  }

}
