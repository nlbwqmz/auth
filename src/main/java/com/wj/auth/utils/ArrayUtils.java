package com.wj.auth.utils;

import com.google.common.base.Strings;
import java.util.Optional;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class ArrayUtils {

  /**
   * 数组不为空，且每一个元素都不为空
   */
  public static boolean isAllNotBlank(String[] array) {
    if (array == null || array.length == 0) {
      return false;
    } else {
      for (String item : array) {
        if (Strings.isNullOrEmpty(item)) {
          return false;
        }
      }
    }
    return true;
  }

  public static String format(String[] array) {
    return format(array, null);
  }

  public static String format(String[] array, String delimiter) {
    delimiter = Optional.ofNullable(delimiter).orElse(",");
    StringBuffer format = new StringBuffer();
    for (int i = 0; i < array.length; i++) {
      if (i == array.length - 1) {
        format.append(array[i] + delimiter);
      } else {
        format.append(array[i]);
      }
    }
    return format.toString();
  }

}
