package com.wj.auth.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wj.auth.common.AlgorithmEnum;
import com.wj.auth.exception.CertificateNotFoundException;
import com.wj.auth.exception.TokenFactoryInitException;
import com.wj.auth.utils.JacksonUtils;
import com.wj.auth.utils.StringUtils;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Enumeration;
import javax.annotation.PostConstruct;
import javax.security.auth.login.CredentialNotFoundException;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.util.ResourceUtils;

/**
 * @Author: weijie
 * @Date: 2020/6/12
 */
@ConfigurationProperties(prefix = "auth.token")
public class TokenFactory {

  /**
   * 公钥
   */
  private RSAPublicKey publicKey;
  /**
   * 私钥
   */
  private RSAPrivateKey privateKey;
  /**
   * 算法
   */
  private Algorithm algorithmObj;
  /**
   * 载体
   */
  private String subjectClaim = "subject";
  /**
   * 过期时间
   */
  private String expireClaim = "expire";
  /**
   * 加密方法
   */
  private String algorithm = "HMAC256";
  /**
   * 密码
   */
  private String secret = "com.wj.auth";
  /**
   * 证书地址
   */
  private String keystorePath;
  /**
   * 证书地址
   */
  private String keystoreSecret;
  /**
   * 发行人
   */
  private String issuer = "com.wj.auth";

  @PostConstruct
  public void init() {
    AlgorithmEnum algorithmEnum;
    try{
      algorithmEnum = AlgorithmEnum.valueOf(algorithm);
    } catch (IllegalArgumentException e){
      throw new TokenFactoryInitException("不支持当前算法[" + algorithm + "]");
    }
    switch (algorithmEnum){
      case HMAC256:
        initHash();
        break;
      case RSA:
        if (keystorePath == null) {
          validThisTimeInit();
        } else {
          initFromKeyStore();
        }
        break;
      default:
        throw new TokenFactoryInitException("[" + algorithm + "]算法不支持");
    }
  }


  /**
   * 通过 证书 获取 RSA公钥私钥 加载私钥另一写法 PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias,
   * "weijie".toCharArray());
   *
   * @throws Exception
   */
  private void initFromKeyStore() {
    try {
      File file = ResourceUtils.getFile(keystorePath);

      FileInputStream inputStream = new FileInputStream(file);
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(inputStream, keystoreSecret.toCharArray());
      Enumeration aliasEnum = keyStore.aliases();
      String keyAlias = "";
      while (aliasEnum.hasMoreElements()) {
        keyAlias = (String) aliasEnum.nextElement();
      }
      Certificate ce = keyStore.getCertificate(keyAlias);

      publicKey = (RSAPublicKey) ce.getPublicKey();
      //加载私钥,这里填私钥密码
      privateKey = (RSAPrivateKey) ((KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias,
          new KeyStore.PasswordProtection(keystoreSecret.toCharArray()))).getPrivateKey();
      algorithmObj = Algorithm.RSA256(publicKey, privateKey);
    } catch (Exception e) {
      e.printStackTrace();
      throw new TokenFactoryInitException();
    }
  }

  /**
   * RSA密钥初始化 每次启动自动生成 本次有效
   */
  private void validThisTimeInit() {
    /* RSA算法要求有一个可信任的随机数源 */
    //获得对象 KeyPairGenerator 参数 RSA 1024个字节
    KeyPairGenerator keyPairGen = null;
    try {
      keyPairGen = KeyPairGenerator.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    keyPairGen.initialize(1024);
    //通过对象 KeyPairGenerator 生成密匙对 KeyPair
    KeyPair keyPair = keyPairGen.generateKeyPair();
    //通过对象 KeyPair 获取RSA公私钥对象RSAPublicKey RSAPrivateKey
    publicKey = (RSAPublicKey) keyPair.getPublic();
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
    algorithmObj = Algorithm.RSA256(publicKey, privateKey);
  }

  private void initHash() {
    algorithmObj = Algorithm.HMAC256(keystoreSecret);
  }

  private JWTCreator.Builder builder(Object obj, long expire) {
    return JWT.create()
        .withIssuer(issuer)
        .withIssuedAt(new Date())
        .withClaim(subjectClaim, JacksonUtils.toJSONString(obj))
        .withClaim(expireClaim, expire);
  }

  public String create(Object obj) {
    return builder(obj, -1).sign(algorithmObj);
  }

  public String create(Object obj, long expire) {
    Builder builder = builder(obj, expire);
    if (expire > 0) {
      return builder.withExpiresAt(new Date(System.currentTimeMillis() + expire)).sign(algorithmObj);
    } else {
      return builder.sign(algorithmObj);
    }
  }

  public void decode(String token){
    if(StringUtils.isBlank(token)){
      throw new CertificateNotFoundException();
    }
    DecodedJWT verify = verify(token);
    SubjectManager.setSubject(JacksonUtils
        .toObject(verify.getClaim(subjectClaim).asString(), Object.class));
    SubjectManager.setExpire(verify.getClaim(expireClaim).asLong());
  }

  public DecodedJWT verify(String authorization) {
    JWTVerifier verifier = JWT.require(algorithmObj)
        .withIssuer(issuer)
        .build();
    DecodedJWT decodedJWT = verifier.verify(authorization);
    return decodedJWT;
  }


  public String getAlgorithm() {
    return algorithm;
  }

  public void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getKeystorePath() {
    return keystorePath;
  }

  public void setKeystorePath(String keystorePath) {
    this.keystorePath = keystorePath;
  }

  public String getKeystoreSecret() {
    return keystoreSecret;
  }

  public void setKeystoreSecret(String keystoreSecret) {
    this.keystoreSecret = keystoreSecret;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }
}
