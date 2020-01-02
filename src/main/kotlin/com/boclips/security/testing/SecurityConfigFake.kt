package com.boclips.security.testing

import com.boclips.security.HttpSecurityConfigurer
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

@Configuration
@EnableWebSecurity
class SecurityConfigFake(val httpSecurityConfigurer: HttpSecurityConfigurer) : WebSecurityConfigurerAdapter() {
    override fun configure(http: HttpSecurity) {
        http
            .cors().disable()
            .csrf().disable()
            .addFilterBefore(FakeAuthorizationFilter(), BasicAuthenticationFilter::class.java)

        httpSecurityConfigurer.configure(http)
    }
}
