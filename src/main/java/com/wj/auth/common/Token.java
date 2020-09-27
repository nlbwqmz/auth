package com.wj.auth.common;

/**
 * @Author: weijie
 * @Date: 2020/9/27
 */
public class Token {
  /**
   * 加密方法
   */
  private String algorithm = "HMAC256";
  /**
   * 密码
   */
  private String password = "com.github.nlbwqmz";
  /**
   * 证书地址
   */
  private String keystoreLocation;
  /**
   * 证书密码
   */
  private String keystorePassword;
  /**
   * 发行人
   */
  private String issuer = "com.github.nlbwqmz";

  public String getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getKeystoreLocation() {
    return keystoreLocation;
  }

  public void setKeystoreLocation(String keystoreLocation) {
    this.keystoreLocation = keystoreLocation;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword) {
    this.keystorePassword = keystorePassword;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }
}
