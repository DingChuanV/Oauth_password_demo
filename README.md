# Oauth_password_demo
Spring Security OAuth2.0之密码模式

## 实现原理

<img src="https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204111801191.png" alt="image-20220411180153181" style="zoom:50%;" />

## 实现步骤

和授权码模式 部署项目一致 只需要更改配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * OAuth2AuthenticationManager 来处理我们密码模式的密码
     *
     * @return org.springframework.security.authentication.AuthenticationManager
     * @author wanglufei
     * @date 2022/4/11 10:44 PM
     */
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    /**
     * 自定义加密逻辑
     *
     * @return org.springframework.security.crypto.password.PasswordEncoder
     * @author wanglufei
     * @date 2022/4/11 6:32 PM
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 自定义web相关的属性
     *
     * @param http
     * @author wanglufei
     * @date 2022/4/11 7:30 PM
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //关闭CSRF防护
        http.csrf().disable()
                //授权
                .authorizeRequests()
                .antMatchers("/oauth/**", "/login/**", "/logout/**")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll();

    }
}
```
```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserDetailsService userDetailsService;

    /**
     * 密码模式是直接将我们的密码传给授权服务器
     * 使用密码所需要的配置
     *
     * @param endpoints
     * @author wanglufei
     * @date 2022/4/11 10:41 PM
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }

    /**
     * 授权服务器的4个端点
     * * - `Authorize Endpoint` ：授权端点，进行授权
     * * - `Token Endpoint` ：令牌端点，进过授权拿到对应的Token
     * * - `Introspection Endpoint`：校验端点，校验Token的合法性
     * * - `Revocat ion Endpoint` ：撤销端点，撒销授权
     *
     * @param clients
     * @author wanglufei
     * @date 2022/4/11 7:47 PM
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                //配置client Id
                .withClient("admin")
                //client-secret
                .secret(passwordEncoder.encode("112233"))
                //配置访问token的有效期
                .accessTokenValiditySeconds(3600)
                //配置重定向的跳转，用于授权成功之后的跳转
                .redirectUris("http://www.baidu.com")
                //作用域
                .scopes("all")
                //Grant_type  密码模式
                .authorizedGrantTypes("password");
    }

}
```
## 测试
<img src="https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112300354.png" alt="image-20220411230011765" style="zoom:50%;" />

<img src="https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112300696.png" alt="image-20220411225942267" style="zoom:50%;" />

<img src="https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112301466.png" alt="image-20220411230110858" style="zoom:50%;" />

## 使用redis存储token 令牌
因为我们的Token令牌 都是放在内存中的 这肯定是不合理的
1. 导入依赖
```xml
        <!--redis依赖-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <!--对象池依赖-->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-pool2</artifactId>
        </dependency>
```
2. 配置redis
```properties
spring.redis.host=localhost
```
3. redisConfig
```java
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
```
4. 在授权服务器中配置
```java
 @Autowired
    @Qualifier("redisTokenStore")
    private TokenStore redisTokenStore;

    /**
     * 密码模式是直接将我们的密码传给授权服务器
     * 使用密码所需要的配置
     *
     * @param endpoints
     * @author wanglufei
     * @date 2022/4/11 10:41 PM
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                //配置使用redis存储token 令牌
                .tokenStore(redisTokenStore);
    }
```
5. 测试

原本redis

![image-20220411232859444](https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112329208.png)

在去PostMan使用原来的测试

![](https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112331360.png)

![](https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112331049.png)

去获取当前用户

<img src="https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112332914.png" alt="image-20220411233231230" style="zoom:50%;" />

在去看看Redis中

![](https://bearbrick0.oss-cn-qingdao.aliyuncs.com/images/img/202204112336154.png)
