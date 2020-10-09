package com.wj.auth.core;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author weijie
 * @since 2020/9/14
 */
public class SubjectManager {

  private static final ThreadLocal<HttpServletRequest> requestLocal = new ThreadLocal<>();
  private static final ThreadLocal<HttpServletResponse> responseLocal = new ThreadLocal<>();
  private static final ThreadLocal<Object> subjectLocal = new ThreadLocal<>();
  private static final ThreadLocal<Long> expireLocal = new ThreadLocal<>();

  public static HttpServletRequest getRequest() {
    return requestLocal.get();
  }

  public static void setRequest(HttpServletRequest request) {
    requestLocal.set(request);
  }

  public static HttpServletResponse getResponse() {
    return responseLocal.get();
  }

  public static void setResponse(HttpServletResponse response) {
    responseLocal.set(response);
  }

  public static Object getSubject() {
    return subjectLocal.get();
  }

  public static void setSubject(Object subject) {
    subjectLocal.set(subject);
  }

  public static long getExpire() {
    return expireLocal.get();
  }

  public static void setExpire(long expire) {
    expireLocal.set(expire);
  }

  public static void removeAll() {
    requestLocal.remove();
    responseLocal.remove();
    subjectLocal.remove();
    expireLocal.remove();
  }
}
