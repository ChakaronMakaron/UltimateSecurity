package com.lemakhno.ua.securityultimate.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AppSecurityFilterChain {

    @Autowired
    private AppAuthenticationFilter appAuthenticationFilter;

    @Autowired
    private AppAuthorizationFilter appAuthorizationFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
        // .cors()
        // .and()
        .csrf().disable()
        .authorizeRequests()
            .antMatchers("/admin/**")
                .hasRole("ADMIN")
            .antMatchers("/user/**")
                .hasAnyRole("USER", "ADMIN")
            .antMatchers("/authorized")
                .authenticated()
            .anyRequest()
                .permitAll();

        httpSecurity
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        httpSecurity
        .addFilterBefore(appAuthorizationFilter, AppAuthenticationFilter.class) // Or UsernamePasswordAuthenticationFilter
        .addFilter(appAuthenticationFilter);

        return httpSecurity.build();
    }
}


