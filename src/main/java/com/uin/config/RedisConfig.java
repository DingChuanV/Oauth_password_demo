package com.uin.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * @author wanglufei
 * @description: 使用redis存储我们的token
 * Redis配置类
 * @date 2022/4/11/11:17 PM
 */

@Configuration
public class RedisConfig {

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    /**
     * TokenStore会自动连接redis，将token存储到redis中
     *
     * @return org.springframework.security.oauth2.provider.token.TokenStore
     * @author wanglufei
     * @date 2022/4/11 11:20 PM
     */
    @Bean
    public TokenStore redisTokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }
}
