package com.wj.auth.common;

import com.wj.auth.exception.AuthException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author weijie
 * @since 2020/10/14
 */
@RestController
@RequestMapping("auth")
public class ErrorController {

  @RequestMapping("error")
  public void error(HttpServletRequest request) {
    AuthException error = (AuthException) request.getAttribute("authError");
    throw error;
  }
}
