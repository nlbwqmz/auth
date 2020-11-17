package com.wj.auth.core.chain;

import com.google.common.base.Joiner;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.CorsConfiguration;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

/**
 * @author 魏杰
 * @since 0.0.2
 */
@Order(0)
@Component
public class CorsAuthChain implements AuthChain {

  private final CorsConfiguration corsConfiguration;

  public CorsAuthChain(AuthAutoConfiguration authAutoConfiguration) {
    corsConfiguration = authAutoConfiguration.getCors();
  }

  @Override
  public void doFilter(ChainManager chain) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
        corsConfiguration.isAccessControlAllowCredentials().toString());
    response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
        Joiner.on(",").join(corsConfiguration.getAccessControlAllowHeaders()));
    response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
        Joiner.on(",").join(corsConfiguration.getAccessControlAllowMethods()));
    response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
        Joiner.on(",").join(corsConfiguration.getAccessControlAllowOrigin()));
    response.setHeader(HttpHeaders.ACCESS_CONTROL_MAX_AGE,
        corsConfiguration.getAccessControlMaxAge().toString());
    chain.doAuth();
  }

  @Override
  public boolean isEnabled() {
    return corsConfiguration.isEnabled();
  }
}
