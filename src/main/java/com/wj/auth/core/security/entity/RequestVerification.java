package com.wj.auth.core.security.entity;

import com.wj.auth.common.Logical;
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
  private Logical logical;

  public RequestVerification() {
  }

  public RequestVerification(Set<String> patterns) {
    this.patterns = patterns;
  }

  public RequestVerification(Set<String> patterns, Set<String> methods) {
    this.patterns = patterns;
    this.methods = methods;
  }

  public RequestVerification(Set<String> patterns, Set<String> methods, String[] auth,
      Logical logical) {
    this.patterns = patterns;
    this.methods = methods;
    this.auth = auth;
    this.logical = logical;
  }

  public Set<String> getPatterns() {
    return patterns;
  }

  public void setPatterns(Set<String> patterns) {
    this.patterns = patterns;
  }

  public Set<String> getMethods() {
    return methods;
  }

  public void setMethods(Set<String> methods) {
    this.methods = methods;
  }

  public String[] getAuth() {
    return auth;
  }

  public void setAuth(String[] auth) {
    this.auth = auth;
  }

  public Logical getLogical() {
    return logical;
  }

  public void setLogical(Logical logical) {
    this.logical = logical;
  }
}
