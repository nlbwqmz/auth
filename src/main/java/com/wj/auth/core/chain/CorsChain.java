package com.wj.auth.core.chain;

import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.Cors;
import com.wj.auth.common.SubjectManager;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(1)
@Component
public class CorsChain implements Chain{

  private final AuthAutoConfiguration authAutoConfiguration;

  public CorsChain(AuthAutoConfiguration authAutoConfiguration) {
    this.authAutoConfiguration = authAutoConfiguration;
  }

  @Override
  public void doFilter(ChainManager chain) {
    HttpServletResponse response = SubjectManager.getResponse();
    Cors cors = authAutoConfiguration.getCors();
    if (cors.isEnabled()) {
      response.setHeader("Access-Control-Allow-Origin", cors.getAccessControlAllowOrigin());
      response.setHeader("Access-Control-Allow-Headers", cors.getAccessControlAllowHeaders());
      response.setHeader("Access-Control-Allow-Methods", cors.getAccessControlAllowMethods());
      response.setHeader("Access-Control-Allow-Credentials",
          String.valueOf(cors.getAccessControlAllowCredentials()));
      response.setHeader("Access-Control-Max-Age", cors.getAccessControlMaxAge());
    }
    chain.doAuth();
  }
}
