package com.wj.auth.xss;

import com.google.common.base.Strings;
import com.google.common.html.HtmlEscapers;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * @author weijie
 * @since 2020/10/13
 */
public class XssAndSqlHttpServletRequestWrapper extends HttpServletRequestWrapper {

  public XssAndSqlHttpServletRequestWrapper(HttpServletRequest request) {
    super(request);
  }

  @Override
  public String getParameter(String name) {
    String value = super.getParameter(name);
    if (!Strings.isNullOrEmpty(value)) {
      value = HtmlEscapers.htmlEscaper().escape(value);
    }
    return value;
  }

  @Override
  public String[] getParameterValues(String name) {
    String[] parameterValues = super.getParameterValues(name);
    if (parameterValues == null) {
      return null;
    }
    for (int i = 0; i < parameterValues.length; i++) {
      String value = parameterValues[i];
      parameterValues[i] = HtmlEscapers.htmlEscaper().escape(value);
    }
    return parameterValues;
  }

}
