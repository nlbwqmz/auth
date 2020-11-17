package com.wj.auth.core.chain;

/**
 * @author 魏杰
 * @since 0.0.2
 */
public interface AuthChain {

  /**
   * 过滤
   *
   * @param chain 过滤链
   */
  void doFilter(ChainManager chain);

  /**
   * 是否启用
   *
   * @return
   */
  boolean isEnabled();

}
