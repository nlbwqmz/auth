package com.wj.auth.core;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wj.auth.common.AlgorithmEnum;
import com.wj.auth.common.AuthConfig;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ResourceUtils;

/**
 * @Author: weijie
 * @Date: 2020/6/12
 */
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

  @Autowired
  private AuthConfig authConfig;

  @PostConstruct
  public void init() {
    AlgorithmEnum algorithmEnum;
    try {
      algorithmEnum = AlgorithmEnum.valueOf(authConfig.getToken().getAlgorithm());
    } catch (IllegalArgumentException e) {
      throw new TokenFactoryInitException("不支持当前算法[" + authConfig.getToken().getAlgorithm() + "]");
    }
    switch (algorithmEnum) {
      case HMAC256:
        initHash();
        break;
      case RSA:
        if (authConfig.getToken().getKeystoreLocation() == null) {
          validThisTimeInit();
        } else {
          initFromKeyStore();
        }
        break;
      default:
        throw new TokenFactoryInitException("[" + authConfig.getToken().getAlgorithm() + "]算法不支持");
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
      File file = ResourceUtils.getFile(authConfig.getToken().getKeystoreLocation());

      FileInputStream inputStream = new FileInputStream(file);
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(inputStream, authConfig.getToken().getKeystorePassword().toCharArray());
      Enumeration aliasEnum = keyStore.aliases();
      String keyAlias = "";
      while (aliasEnum.hasMoreElements()) {
        keyAlias = (String) aliasEnum.nextElement();
      }
      Certificate ce = keyStore.getCertificate(keyAlias);

      publicKey = (RSAPublicKey) ce.getPublicKey();
      //加载私钥,这里填私钥密码
      privateKey = (RSAPrivateKey) ((KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias,
          new KeyStore.PasswordProtection(authConfig.getToken().getKeystorePassword().toCharArray()))).getPrivateKey();
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
    KeyPairGenerator keyPairGen = null;
    try {
      keyPairGen = KeyPairGenerator.getInstance(authConfig.getToken().getAlgorithm());
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    keyPairGen.initialize(1024);
    KeyPair keyPair = keyPairGen.generateKeyPair();
    publicKey = (RSAPublicKey) keyPair.getPublic();
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
    algorithmObj = Algorithm.RSA256(publicKey, privateKey);
  }

  private void initHash() {
    algorithmObj = Algorithm.HMAC256(authConfig.getToken().getKeystorePassword());
  }

  private JWTCreator.Builder builder(Object obj, long expire) {
    return JWT.create()
        .withIssuer(authConfig.getToken().getIssuer())
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
      return builder.withExpiresAt(new Date(System.currentTimeMillis() + expire))
          .sign(algorithmObj);
    } else {
      return builder.sign(algorithmObj);
    }
  }

  public void decode(String token) {
    if (StringUtils.isBlank(token)) {
      throw new CertificateNotFoundException();
    }
    DecodedJWT verify = verify(token);
    SubjectManager.setSubject(JacksonUtils
        .toObject(verify.getClaim(subjectClaim).asString(), Object.class));
    SubjectManager.setExpire(verify.getClaim(expireClaim).asLong());
  }

  public DecodedJWT verify(String authorization) {
    JWTVerifier verifier = JWT.require(algorithmObj)
        .withIssuer(authConfig.getToken().getIssuer())
        .build();
    DecodedJWT decodedJWT = verifier.verify(authorization);
    return decodedJWT;
  }
}
