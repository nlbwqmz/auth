package com.wj.auth.core.chain;

import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.core.cors.configuration.CorsConfiguration;
import com.wj.auth.common.SubjectManager;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(2)
@Component
public class CorsChain implements Chain{

  private final AuthAutoConfiguration authAutoConfiguration;

  public CorsChain(AuthAutoConfiguration authAutoConfiguration) {
    this.authAutoConfiguration = authAutoConfiguration;
  }

  @Override
  public void doFilter(ChainManager chain) {
    HttpServletResponse response = SubjectManager.getResponse();
    CorsConfiguration corsConfiguration = authAutoConfiguration.getCors();
    if (corsConfiguration.isEnabled()) {
      response.setHeader("Access-Control-Allow-Origin", corsConfiguration.getAccessControlAllowOrigin());
      response.setHeader("Access-Control-Allow-Headers", corsConfiguration.getAccessControlAllowHeaders());
      response.setHeader("Access-Control-Allow-Methods", corsConfiguration.getAccessControlAllowMethods());
      response.setHeader("Access-Control-Allow-Credentials",
          String.valueOf(corsConfiguration.getAccessControlAllowCredentials()));
      response.setHeader("Access-Control-Max-Age", corsConfiguration.getAccessControlMaxAge());
    }
    chain.doAuth();
  }
}
