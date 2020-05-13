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
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy

@Configuration
//Keycloak bug: https://issues.jboss.org/browse/KEYCLOAK-8725
@ComponentScan(
    basePackageClasses = [KeycloakSecurityComponents::class],
    excludeFilters = [
        ComponentScan.Filter(
            type = FilterType.REGEX,
            pattern = ["org.keycloak.adapters.springsecurity.management.HttpSessionManager"]
        )
    ]
)
@EnableWebSecurity
class KeycloakSecurityConfig(val httpSecurityConfigurer: HttpSecurityConfigurer) :
    KeycloakWebSecurityConfigurerAdapter() {

    @Autowired
    fun configureGlobal(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(keycloakAuthenticationProvider())
    }

    /**
     * Our services will consume JWT tokens, and are therefore stateless.
     *
     * Session management may be needed if the service provides tokens so that concurrent access can be controlled
     *   (see https://github.com/keycloak/keycloak-documentation/blob/master/securing_apps/topics/oidc/java/spring-security-adapter.adoc
     *   for further details).
     *
     *   See https://stackoverflow.com/questions/61771649/why-confidential-and-public-clients-require-apps-to-handle-sessions-in-the-sprin
     *   for a hopefully enlightening forum.
     */
    @Bean
    override fun sessionAuthenticationStrategy(): SessionAuthenticationStrategy {
        return NullAuthenticatedSessionStrategy()
    }

    override fun configure(http: HttpSecurity) {
        super.configure(http)
        http.csrf().disable()
        httpSecurityConfigurer.configure(http)
    }
}

