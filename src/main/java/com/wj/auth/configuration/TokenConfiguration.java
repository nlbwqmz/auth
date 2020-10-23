package com.wj.auth.configuration;

import com.wj.auth.core.security.configuration.AlgorithmEnum;

/**
 * token配置
 *
 * @author weijie
 * @since 2020/9/27
 */
public class TokenConfiguration {

  /**
   * 加密方法
   */
  private AlgorithmEnum algorithm = AlgorithmEnum.HMAC256;
  /**
   * 密码
   */
  private String password = "nlbwqmz.github.io";
  /**
   * 证书地址
   */
  private String keystoreLocation;
  /**
   * 发行人
   */
  private String issuer = "nlbwqmz.github.io";

  public AlgorithmEnum getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(AlgorithmEnum algorithm) {
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

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }
}
