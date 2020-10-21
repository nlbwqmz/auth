package com.wj.auth.common;

import com.wj.auth.core.security.configuration.Logical;
import java.util.Set;

/**
 * 请求验证
 *
 * @author weijie
 * @since 2020/9/18
 */
public class AuthHelper {

  private Set<String> patterns;
  private Set<String> methods;
  private String[] auth;
  private Logical logical;

  private AuthHelper() {

  }

  public static AuthBuilder authBuilder() {
    return new AuthBuilder().setLogical(Logical.AND);
  }

  public static AnonBuilder otherBuilder() {
    return new AnonBuilder();
  }

  public Set<String> getPatterns() {
    return patterns;
  }

  public AuthHelper setPatterns(Set<String> patterns) {
    this.patterns = patterns;
    return this;
  }

  public Set<String> getMethods() {
    return methods;
  }

  public AuthHelper setMethods(Set<String> methods) {
    this.methods = methods;
    return this;
  }

  public String[] getAuth() {
    return auth;
  }

  public AuthHelper setAuth(String... auth) {
    this.auth = auth;
    return this;
  }

  public Logical getLogical() {
    return logical;
  }

  public AuthHelper setLogical(Logical logical) {
    this.logical = logical;
    return this;
  }

  public static class AuthBuilder {

    private AuthHelper authHelper = new AuthHelper();

    public AuthBuilder setPatterns(Set<String> patterns) {
      authHelper.setPatterns(patterns);
      return this;
    }

    public AuthBuilder setMethods(Set<String> methods) {
      authHelper.setMethods(methods);
      return this;
    }

    public AuthBuilder setAuth(String... auth) {
      authHelper.setAuth(auth);
      return this;
    }

    public AuthBuilder setLogical(Logical logical) {
      authHelper.setLogical(logical);
      return this;
    }

    public AuthHelper build() {
      return authHelper;
    }
  }

  public static class AnonBuilder {

    private AuthHelper authHelper = new AuthHelper();

    public AnonBuilder setPatterns(Set<String> patterns) {
      authHelper.setPatterns(patterns);
      return this;
    }

    public AnonBuilder setMethods(Set<String> methods) {
      authHelper.setMethods(methods);
      return this;
    }

    public AuthHelper build() {
      return authHelper;
    }
  }
}
