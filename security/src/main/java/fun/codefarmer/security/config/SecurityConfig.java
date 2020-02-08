package fun.codefarmer.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 *  单个 security 配置，为方便配置多个security 这个先注释掉
 * @ @ClassName SecurityConfig
 * @ Descriotion TODO
 * @ Author admin
 * @ Date 2020/2/7 13:29
 **/
//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //加密实例，此处告诉程序不加密
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()//基于内存的认证
        .withUser("codefarmer").password("123").roles("admin")
                .and()
                .withUser("千里").password("456").roles("user");

    }
    // http 网络安全

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()//开启配置
                //路径匹配符                            //具备角色
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasAnyRole("admin", "user")
                //另一种多角色方法
                //.antMatchers("/user/**").access("hasAnyRole('user','admin')")
                //除上述两个路径，其余的只要认证都可访问
                .anyRequest().authenticated()
                //
                .and()
                //表单登录
                .formLogin()
                //处理表单登录的url 就是处理登录的接口
                .loginProcessingUrl("/doLogin")//路径不对 登录不进去 忘记写 /  导致登录不进去
                //登录页面
                .loginPage("/login")
                .usernameParameter("uname")
                .passwordParameter("passwd")
                //登录成功配置
                .successHandler(new AuthenticationSuccessHandler() {
                    /**
                     * @param request        请求
                     * @param response       响应
                     * @param authentication 保存登录成功的信息
                     * @throws IOException
                     * @throws ServletException
                     */
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //登录失败配置
                .failureHandler(new AuthenticationFailureHandler() {
                    /**
                     *
                     * @param request
                     * @param response
                     * @param e
                     * @throws IOException
                     * @throws ServletException
                     */
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        HashMap<String, Object> map = new HashMap<>();
                        map.put("status",401);
                        if (e instanceof LockedException) {
                            map.put("msg", "账户被锁定");
                        } else if (e instanceof BadCredentialsException) {
                            map.put("msg","用户名会密码错误");
                        } else if (e instanceof DisabledException) {
                            map.put("msg", "账户被禁用");
                        } else if (e instanceof AccessDecisionManager) {
                            map.put("msg", "账户过期");
                        } else if (e instanceof CredentialsExpiredException) {
                            map.put("msg", "密码过期");
                        } else {
                            map.put("msg", "登录失败");
                        }
                    }
                })


                //与登录相关的接口直接过
                .permitAll()
                //注销配置
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    /**
                     *
                     * @param request
                     * @param response
                     * @param authentication
                     * @throws IOException
                     * @throws ServletException
                     */
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        HashMap<Object, Object> map = new HashMap<>();
                        map.put("status", 200);
                        map.put("msg", "注销成功");
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();

                    }
                })
                .and()
                //关闭csr攻击，postman 测试，防止判断成时csr攻击
                .csrf().disable();

    }
}
