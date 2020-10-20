package com.wj.auth.core;

import com.wj.auth.common.SubjectManager;
import com.wj.auth.configuration.AuthAutoConfiguration;
import com.wj.auth.configuration.SecurityConfiguration;
import com.wj.auth.core.security.AuthTokenGenerate;
import com.wj.auth.utils.JacksonUtils;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Component
public class Login {

  private final SecurityConfiguration security;
  private final AuthTokenGenerate authTokenGenerate;

  public Login(AuthAutoConfiguration authAutoConfiguration,
      AuthTokenGenerate authTokenGenerate) {
    this.security = authAutoConfiguration.getSecurity();
    this.authTokenGenerate = authTokenGenerate;
  }

  /**
   * 登录
   *
   * @param obj
   * @param duration
   * @param timeUnit
   */
  public void doLogin(Object obj, long duration, TimeUnit timeUnit) {
    doLogin(obj, timeUnit.toMillis(duration));
  }

  /**
   * 登录
   *
   * @param obj
   * @param expire 毫秒
   */
  public void doLogin(Object obj, long expire) {
    HttpServletResponse response = SubjectManager.getResponse();
    response.setHeader(security.getHeader(),
        authTokenGenerate.create(JacksonUtils.toJSONString(obj), expire));
    response.setHeader("Access-Control-Expose-Headers", security.getHeader());
  }

}
