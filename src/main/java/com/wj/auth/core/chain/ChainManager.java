package com.wj.auth.core.chain;

import java.util.List;
import org.springframework.stereotype.Component;

/**
 * @author weijie
 * @since 2020/9/10
 */
@Component
public class ChainManager {

  private final List<Chain> chains;
  private int chainIndex = 0;

  public ChainManager(List<Chain> chains) {
    this.chains = chains;
  }

  public void doAuth() {
    if (chainIndex < chains.size()) {
      chains.get(chainIndex++).doFilter(this);
    }
  }
}
