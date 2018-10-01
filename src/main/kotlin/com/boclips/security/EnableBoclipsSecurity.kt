package com.boclips.security

import com.boclips.security.keycloak.KeycloakSecurityConfig
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Import
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FILE)
@Import(KeycloakSecurityConfig::class)
annotation class EnableBoclipsSecurity