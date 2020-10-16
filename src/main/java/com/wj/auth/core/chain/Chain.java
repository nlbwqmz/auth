package com.wj.auth.core.chain;

/**
 * @author weijie
 * @since 2020/10/16
 */
public interface Chain {

  void doFilter(ChainManager chain);

}
