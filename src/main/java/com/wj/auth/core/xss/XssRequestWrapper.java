package com.wj.auth.core.xss;

import com.google.common.base.Strings;
import com.google.common.html.HtmlEscapers;
import com.wj.auth.exception.xss.XssException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * @author weijie
 * @since 2020/10/13
 */
public class XssRequestWrapper extends HttpServletRequestWrapper {

  private final boolean queryEnable;
  private final boolean bodyEnable;

  public XssRequestWrapper(HttpServletRequest request, boolean queryEnable, boolean bodyEnable) {
    super(request);
    this.queryEnable = queryEnable;
    this.bodyEnable = bodyEnable;
  }

  @Override
  public String getParameter(String name) {
    String value = super.getParameter(name);
    if (queryEnable && !Strings.isNullOrEmpty(value)) {
      value = HtmlEscapers.htmlEscaper().escape(value);
    }
    return value;
  }

  @Override
  public String[] getParameterValues(String name) {
    String[] parameterValues = super.getParameterValues(name);
    if (queryEnable) {
      if (parameterValues == null) {
        return null;
      }
      for (int i = 0; i < parameterValues.length; i++) {
        String value = parameterValues[i];
        if (!Strings.isNullOrEmpty(value)) {
          parameterValues[i] = HtmlEscapers.htmlEscaper().escape(value);
        }
      }
    }
    return parameterValues;
  }

  @Override
  public ServletInputStream getInputStream() throws IOException {
    ServletInputStream servletInputStream = super.getInputStream();
    if (bodyEnable) {
      final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
          inputHandlers(servletInputStream).getBytes());
      return new ServletInputStream() {
        @Override
        public int read() throws IOException {
          return byteArrayInputStream.read();
        }

        @Override
        public boolean isFinished() {
          return false;
        }

        @Override
        public boolean isReady() {
          return false;
        }

        @Override
        public void setReadListener(ReadListener listener) {

        }
      };
    } else {
      return servletInputStream;
    }
  }

  public String inputHandlers(ServletInputStream servletInputStream) {
    StringBuilder sb = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(servletInputStream, Charset.forName("UTF-8")))) {
      String line = "";
      while ((line = reader.readLine()) != null) {
        System.out.println(line);
        sb.append(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
      throw new XssException();
    } finally {
      if (servletInputStream != null) {
        try {
          servletInputStream.close();
        } catch (IOException e) {
          e.printStackTrace();
          throw new XssException();
        }
      }
    }
    return XssObjectMapper.doXss(sb.toString());
  }


}
