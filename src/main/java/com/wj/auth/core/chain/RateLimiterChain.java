package com.wj.auth.core.chain;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.RateLimiter;
import com.wj.auth.common.AuthAutoConfiguration;
import com.wj.auth.common.FilterRange;
import com.wj.auth.common.SubjectManager;
import com.wj.auth.core.rateLimiter.RateLimiterCondition;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration;
import com.wj.auth.core.rateLimiter.configuration.RateLimiterConfiguration.Strategy;
import com.wj.auth.core.security.configuration.RequestVerification;
import com.wj.auth.exception.rate.RateLimiterException;
import com.wj.auth.utils.CollectionUtils;
import com.wj.auth.utils.MatchUtils;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
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

  private final RateLimiterConfiguration rateLimiterConfiguration;
  private final RateLimiter rateLimiter;
  private final LoadingCache<String, RateLimiter> cache;
  private final RateLimiterCondition rateLimiterCondition;
  @Value("${server.servlet.context-path:}")
  private String contextPath;
  private ImmutableSet<RequestVerification> ignored;
  private ImmutableSet<RequestVerification> only;

  public RateLimiterChain(AuthAutoConfiguration authAutoConfiguration,
      @Autowired(required = false) RateLimiterCondition rateLimiterCondition) {
    this.rateLimiterConfiguration = authAutoConfiguration.getRateLimiter();
    this.rateLimiterCondition = rateLimiterCondition;
    if (rateLimiterConfiguration.getStrategy() == Strategy.NORMAL) {
      this.cache = null;
      this.rateLimiter = RateLimiter.create(rateLimiterConfiguration.getThreshold());
    } else {
      this.rateLimiter = null;
      this.cache = CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.HOURS)
          .build(new CacheLoader<String, RateLimiter>() {
            @Override
            public RateLimiter load(String key) throws Exception {
              return RateLimiter.create(rateLimiterConfiguration.getThreshold());
            }
          });
    }

  }
  public void setRateLimiter(Set<RequestVerification> rateLimiterSet,
      Set<RequestVerification> rateLimiterIgnoredSet) {
    Set<String> only = rateLimiterConfiguration.getOnly();
    Set<String> ignored = rateLimiterConfiguration.getIgnored();
    if(CollectionUtils.isNotBlank(only)){
      rateLimiterSet.add(RequestVerification.build().setPatterns(CollectionUtils.addUrlPrefix(only, contextPath)));
    }
    if(CollectionUtils.isNotBlank(ignored)){
      rateLimiterIgnoredSet.add(RequestVerification.build().setPatterns(CollectionUtils.addUrlPrefix(ignored, contextPath)));
    }
    this.only = ImmutableSet.copyOf(rateLimiterSet);
    this.ignored = ImmutableSet.copyOf(rateLimiterIgnoredSet);
  }

  @Override
  public void doFilter(ChainManager chain) {
    if (rateLimiterConfiguration.isEnabled() && checkIsLimit()) {
      switch (rateLimiterConfiguration.getStrategy()) {
        case NORMAL:
          normal();
          break;
        case IP:
          condition(getIp());
          break;
        case CUSTOM:
          condition(rateLimiterCondition
              .getCondition(SubjectManager.getRequest(), SubjectManager.getSubject()));
          break;
        default:
          throw new RateLimiterException("rate limiter configuration strategy cannot match");
      }
    }
    chain.doAuth();
  }

  private boolean checkIsLimit() {
    String uri = SubjectManager.getRequest().getRequestURI();
    String method = SubjectManager.getRequest().getMethod();
    FilterRange defaultFilterRange = rateLimiterConfiguration.getDefaultFilterRange();
    switch (defaultFilterRange){
      case ALL: return !MatchUtils.matcher(ignored, uri, method);
      case NONE: return MatchUtils.matcher(only, uri, method);
      default:throw new RateLimiterException("rate limiter configuration defaultFilterRange cannot match");
    }
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
