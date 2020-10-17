package com.wj.auth.core.chain;

/**
 * @author weijie
 * @since 2020/10/16
 */
public interface Chain {

  /**
   * 过滤
   *
   * @param chain 过滤链
   */
  void doFilter(ChainManager chain);

}
