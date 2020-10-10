package com.wj.auth.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wj.auth.exception.JsonException;

/**
 * @author 魏杰
 * @since 2020/5/3
 * @Description:
 */
public class JacksonUtils {

  private static final ObjectMapper mapper = new ObjectMapper();

  public static String toJSONString(Object object) {
    try {
      return mapper.writeValueAsString(object);
    } catch (JsonProcessingException e) {
      e.printStackTrace();
      throw new JsonException(e.getMessage());
    }
  }

  public static <T> T toObject(String json, Class<T> clazz) {
    try {
      return mapper.readValue(json, clazz);
    } catch (JsonProcessingException e) {
      e.printStackTrace();
      throw new JsonException(e.getMessage());
    }
  }
}
