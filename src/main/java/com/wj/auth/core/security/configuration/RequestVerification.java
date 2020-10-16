package com.wj.auth.core.security.configuration;

import java.util.Set;

/**
 * 请求验证
 *
 * @author weijie
 * @since 2020/9/18
 */
public class RequestVerification {

  private Set<String> patterns;
  private Set<String> methods;
  private String[] auth;
  private Logical logical = Logical.AND;

  private RequestVerification() {

  }

  public static RequestVerification build() {
    return new RequestVerification();
  }

  public Set<String> getPatterns() {
    return patterns;
  }

  public RequestVerification setPatterns(Set<String> patterns) {
    this.patterns = patterns;
    return this;
  }

  public Set<String> getMethods() {
    return methods;
  }

  public RequestVerification setMethods(Set<String> methods) {
    this.methods = methods;
    return this;
  }

  public String[] getAuth() {
    return auth;
  }

  public RequestVerification setAuth(String... auth) {
    this.auth = auth;
    return this;
  }

  public Logical getLogical() {
    return logical;
  }

  public RequestVerification setLogical(Logical logical) {
    this.logical = logical;
    return this;
  }
}
