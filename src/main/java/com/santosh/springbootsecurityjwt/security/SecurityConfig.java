package com.santosh.springbootsecurityjwt.security;

import com.santosh.springbootsecurityjwt.security.provider.AuthProvider;
import com.santosh.springbootsecurityjwt.security.provider.BasicAuthProvider;
import com.santosh.springbootsecurityjwt.security.provider.LoginAuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private AuthProvider authProvider;
    @Autowired
    private LoginAuthProvider loginAuthProvider;
    @Autowired
    private BasicAuthProvider basicAuthProvider;
    @Autowired
    private AuthEntryPoint authEntryPoint;

    public AuthenticationFilter authTokenFilter() {
        AuthenticationFilter filter = new AuthenticationFilter(new OrRequestMatcher(
                new AntPathRequestMatcher("/rest/**")
                , new AntPathRequestMatcher("/api/**")
        ), tokenAuthManager());
        filter.setAuthenticationSuccessHandler(new AuthSuccessHandler());
        filter.setAuthenticationFailureHandler(new AuthFailureHandler());
        return filter;
    }

    public BasicAuthFilter basicAuthTokenFilter() {
        BasicAuthFilter filter = new BasicAuthFilter(new AntPathRequestMatcher("/system/**")
                , basicAuthManager());
        filter.setAuthenticationSuccessHandler(new AuthSuccessHandler());
        filter.setAuthenticationFailureHandler(new AuthFailureHandler());
        return filter;
    }

    @Bean
    @Primary
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(loginAuthProvider, authProvider, basicAuthProvider));
    }

    @Bean
    public AuthenticationManager tokenAuthManager() {
        return new ProviderManager(authProvider);
    }

    @Bean
    public AuthenticationManager basicAuthManager() {
        return new ProviderManager(basicAuthProvider);
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                // allow anonymous resource requests
                .antMatchers(
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js",
                        "/h2-console/**"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/**").permitAll()
                .antMatchers("/api/**").authenticated()
                .antMatchers("/system/**").authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authEntryPoint)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Add a filter to validate the tokens with every request
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(basicAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
