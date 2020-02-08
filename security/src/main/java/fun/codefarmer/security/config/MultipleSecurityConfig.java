package fun.codefarmer.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 多个http security 不需要 extends WebSecurityConfigurerAdapter
 * @ @ClassName MultipleSecurityConfig
 * @ Descriotion TODO
 * @ Author admin
 * @ Date 2020/2/7 16:44
 **/
@Configuration
// 此注解时开启方法安全的
                            //第一个参数方法前|方法后 都进行校验
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class MultipleSecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
        //如果使用加密的密码 返回值应为 return new BCryptPasswordEncoder();
    }

    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()//基于内存的认证
                .withUser("codefarmer").password("111").roles("admin")
                .and()
                .withUser("千里").password("222").roles("user");

    }

    // 静态内部类
    @Configuration
    @Order(1)
    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // 只有 /admin/**  地址才会进入后面的配置
            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasAnyRole("admin");
        }
    }

    /**
     * security 与上面的匹配，匹配不上在与下面的匹配
     */
    @Configuration
    public static class OtherSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests().anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/doLogin")
                    .permitAll()
                    .and()
                    .csrf().disable();
        }
    }


}
