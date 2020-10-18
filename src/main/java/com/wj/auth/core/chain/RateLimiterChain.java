package com.wj.auth.core.chain;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.rateLimiter.RateLimiterCondition;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration.Strategy;
import com.wj.auth.exception.rate.RateLimiterException;
import com.wj.auth.utils.AuthUtils;
import com.wj.auth.utils.CollectionUtils;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/10/16
 */
@Order(0)
@Component
public class RateLimiterChain implements Chain {

  private final RateLimiterConfiguration configuration;
  private final RateLimiter rateLimiter;
  private final LoadingCache<String, RateLimiter> cache;
  private final RateLimiterCondition rateLimiterCondition;
  @Value("${server.servlet.context-path:}")
  private String contextPath;
  private Set<String> ignored;
  private Set<String> only;

  public RateLimiterChain(AuthAutoConfiguration authAutoConfiguration,
      @Autowired(required = false) RateLimiterCondition rateLimiterCondition) {
    this.configuration = authAutoConfiguration.getRateLimiter();
    this.rateLimiterCondition = rateLimiterCondition;
    if (configuration.getStrategy() == Strategy.NORMAL) {
      this.cache = null;
      this.rateLimiter = RateLimiter.create(configuration.getThreshold());
    } else {
      this.rateLimiter = null;
      this.cache = CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS)
          .build(new CacheLoader<String, RateLimiter>() {
            @Override
            public RateLimiter load(String key) throws Exception {
              return RateLimiter.create(configuration.getThreshold());
            }
          });
    }

  }

  @PostConstruct
  public void init() {
    Set<String> only = configuration.getOnly();
    if (CollectionUtils.isNotBlank(only)) {
      this.only = CollectionUtils.addUrlPrefix(only, contextPath);
    } else {
      Set<String> ignored = configuration.getIgnored();
      if (CollectionUtils.isNotBlank(ignored)) {
        this.ignored = CollectionUtils.addUrlPrefix(ignored, contextPath);
      }
    }
  }

  @Override
  public void doFilter(ChainManager chain) {
    if (configuration.isEnabled() && checkIsLimit()) {
      switch (configuration.getStrategy()) {
        case NORMAL:
          normal();
          break;
        case IP:
          condition(getIp());
          break;
        case CUSTOM:
          condition(rateLimiterCondition
              .getCondition(SubjectManager.getRequest(), SubjectManager.getResponse()));
          break;
        default:
          throw new RateLimiterException("unknown exception");
      }
    }
    chain.doAuth();
  }

  private boolean checkIsLimit() {
    String uri = SubjectManager.getRequest().getRequestURI();
    if (CollectionUtils.isNotBlank(only)) {
      return AuthUtils.matcher(only, uri);
    }
    if (CollectionUtils.isNotBlank(ignored)) {
      return !AuthUtils.matcher(ignored, uri);
    }
    return true;
  }

  private void normal() {
    if (!rateLimiter.tryAcquire()) {
      throw new RateLimiterException("busy service");
    }
  }

  private void condition(String condition) {
    try {
      if (!cache.get(condition).tryAcquire()) {
        throw new RateLimiterException("busy service");
      }
    } catch (ExecutionException e) {
      e.printStackTrace();
      throw new RateLimiterException(e.getMessage());
    }
  }

  /**
   * TODO 获取IP地址
   */
  private String getIp() {
    return "";
  }
}
