package com.wj.auth.core.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Strings;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.security.entity.AlgorithmEnum;
import com.wj.auth.core.security.entity.Token;
import com.wj.auth.exception.CertificateException;
import com.wj.auth.exception.CertificateNotFoundException;
import com.wj.auth.exception.TokenFactoryInitException;
import com.wj.auth.utils.JacksonUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

/**
 * @author weijie
 * @since 2020/6/12
 */
@Component
public class AuthTokenGenerate {

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
  private AuthAutoConfiguration authAutoConfiguration;

  private Token token;

  @PostConstruct
  public void init() {
    token = authAutoConfiguration.getToken();
    AlgorithmEnum algorithmEnum;
    try {
      algorithmEnum = AlgorithmEnum.valueOf(token.getAlgorithm());
    } catch (IllegalArgumentException e) {
      throw new TokenFactoryInitException(
          String.format("The algorithm %s is not supported", token.getAlgorithm()));
    }
    switch (algorithmEnum) {
      case HMAC256:
        initHMAC256();
        break;
      case RSA:
        if (Strings.isNullOrEmpty(token.getKeystoreLocation())) {
          validThisTimeInit();
        } else {
          initFromKeyStore();
        }
        break;
      default:
        throw new TokenFactoryInitException(
            String.format("The algorithm %s is not supported", token.getAlgorithm()));
    }
  }

  private void initFromKeyStore() {
    File file = null;
    try {
      file = ResourceUtils.getFile(token.getKeystoreLocation());
    } catch (FileNotFoundException e) {
      e.printStackTrace();
      throw new TokenFactoryInitException(e.getMessage());
    }
    try (FileInputStream inputStream = new FileInputStream(file)) {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(inputStream, token.getPassword().toCharArray());
      Enumeration aliasEnum = keyStore.aliases();
      String keyAlias = "";
      while (aliasEnum.hasMoreElements()) {
        keyAlias = (String) aliasEnum.nextElement();
      }
      Certificate ce = keyStore.getCertificate(keyAlias);

      publicKey = (RSAPublicKey) ce.getPublicKey();
      privateKey = (RSAPrivateKey) ((KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias,
          new KeyStore.PasswordProtection(token.getPassword().toCharArray())))
          .getPrivateKey();
      algorithmObj = Algorithm.RSA256(publicKey, privateKey);
    } catch (Exception e) {
      e.printStackTrace();
      throw new TokenFactoryInitException(e.getMessage());
    }
  }

  /**
   * RSA密钥初始化 每次启动自动生成 当次有效
   */
  private void validThisTimeInit() {
    KeyPairGenerator keyPairGen = null;
    try {
      keyPairGen = KeyPairGenerator.getInstance(token.getAlgorithm());
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      throw new TokenFactoryInitException();
    }
    keyPairGen.initialize(1024);
    KeyPair keyPair = keyPairGen.generateKeyPair();
    publicKey = (RSAPublicKey) keyPair.getPublic();
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
    algorithmObj = Algorithm.RSA256(publicKey, privateKey);
  }

  private void initHMAC256() {
    algorithmObj = Algorithm.HMAC256(token.getPassword());
  }

  private JWTCreator.Builder builder(Object obj, long expire) {
    return JWT.create()
        .withIssuer(token.getIssuer())
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
    if (Strings.isNullOrEmpty(token)) {
      throw new CertificateNotFoundException();
    }
    DecodedJWT verify = verify(token);
    SubjectManager.setSubject(JacksonUtils
        .toObject(verify.getClaim(subjectClaim).asString(), Object.class));
    SubjectManager.setExpire(verify.getClaim(expireClaim).asLong());
  }

  public DecodedJWT verify(String authorization) {
    JWTVerifier verifier = JWT.require(algorithmObj)
        .withIssuer(token.getIssuer())
        .build();
    try {
      DecodedJWT decodedJWT = verifier.verify(authorization);
      return decodedJWT;
    } catch (Exception e) {
      throw new CertificateException(e.getMessage());
    }
  }
}
