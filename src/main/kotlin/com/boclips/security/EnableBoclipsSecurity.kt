package com.boclips.security

import com.boclips.security.keycloak.KeycloakSecurityConfig
import org.springframework.context.annotation.Import

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FILE)
@Import(KeycloakSecurityConfig::class)
annotation class EnableBoclipsSecurity