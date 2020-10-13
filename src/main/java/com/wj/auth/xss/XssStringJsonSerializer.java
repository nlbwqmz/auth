package com.wj.auth.xss;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.google.common.html.HtmlEscapers;
import java.io.IOException;

/**
 * @author weijie
 * @since 2020/10/13
 */
public class XssStringJsonSerializer extends JsonSerializer<String> {

  @Override
  public Class<String> handledType() {
    return String.class;
  }

  @Override
  public void serialize(String value, JsonGenerator jsonGenerator,
      SerializerProvider serializerProvider) throws IOException {
    if (value != null) {
      String encodedValue = HtmlEscapers.htmlEscaper().escape(value);
      jsonGenerator.writeString(encodedValue);
    }
  }

}

