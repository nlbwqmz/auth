package com.wj.auth.core.chain;

import java.util.List;

/**
 * @author 魏杰
 * @since 0.0.1
 */
public class ChainManager {

  private boolean isOptionsAndSkipAndDone = false;
  private final List<AuthChain> authChains;
  private final boolean isOptionsAndSkip;
  private int chainIndex = 0;

  public ChainManager(List<AuthChain> authChains, boolean isOptionsAndSkip) {
    this.authChains = authChains;
    this.isOptionsAndSkip = isOptionsAndSkip;
  }

  public void doAuth() {
    if (isOptionsAndSkip) {
      if (!isOptionsAndSkipAndDone) {
        CorsAuthChain corsAuthChain = null;
        for (AuthChain item : authChains) {
          if (item instanceof CorsAuthChain) {
            corsAuthChain = (CorsAuthChain) item;
            break;
          }
        }
        if (corsAuthChain != null) {
          isOptionsAndSkipAndDone = true;
          corsAuthChain.doFilter(this);
        }
      }
    } else {
      if (chainIndex < authChains.size()) {
        authChains.get(chainIndex++).doFilter(this);
      }
    }

  }
}
