package com.wj.auth.core.xss;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.base.Strings;
import com.google.common.html.HtmlEscapers;
import com.wj.auth.exception.xss.XssException;
import java.io.IOException;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

/**
 * @author weijie
 * @since 2020/11/5
 */
public class XssObjectMapper {

  private final static ObjectMapper objectMapper = new Jackson2ObjectMapperBuilder()
      .createXmlMapper(false).build();

  static {
    SimpleModule xssModule = new SimpleModule("xssSerializer");
    xssModule.addSerializer(new JsonSerializer<String>() {
      @Override
      public void serialize(String value, JsonGenerator jsonGenerator,
          SerializerProvider serializerProvider) throws IOException {
        if (!Strings.isNullOrEmpty(value)) {
          jsonGenerator.writeString(HtmlEscapers.htmlEscaper().escape(value));
        } else {
          jsonGenerator.writeString(value);
        }
      }

      @Override
      public Class<String> handledType() {
        return String.class;
      }
    });
    objectMapper.registerModule(xssModule);
  }

  public static String doXss(String value) {
    try {
      Object obj = objectMapper.readValue(value, Object.class);
      return objectMapper.writeValueAsString(obj);
    } catch (JsonProcessingException e) {
      e.printStackTrace();
      throw new XssException(e.getMessage());
    }
  }
}
