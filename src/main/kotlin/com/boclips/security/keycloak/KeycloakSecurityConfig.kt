package com.boclips.security.keycloak

import com.boclips.security.HttpSecurityConfigurer
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.FilterType
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy

@Configuration
//Keycloak bug: https://issues.jboss.org/browse/KEYCLOAK-8725
@ComponentScan(
        basePackageClasses = [KeycloakSecurityComponents::class],
        excludeFilters = [
            ComponentScan.Filter(type = FilterType.REGEX, pattern = ["org.keycloak.adapters.springsecurity.management.HttpSessionManager"])
        ])
@EnableWebSecurity
class KeycloakSecurityConfig(val httpSecurityConfigurer: HttpSecurityConfigurer) : KeycloakWebSecurityConfigurerAdapter() {
    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    fun configureGlobal(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(keycloakAuthenticationProvider())
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    override fun sessionAuthenticationStrategy(): SessionAuthenticationStrategy {
        return RegisterSessionAuthenticationStrategy(SessionRegistryImpl())
    }

    override fun configure(http: HttpSecurity) {
        super.configure(http)
        http.csrf().disable()
        httpSecurityConfigurer.configure(http)
    }
}

