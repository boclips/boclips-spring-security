package com.boclips.security.utils

import org.keycloak.KeycloakPrincipal
import org.springframework.security.core.context.SecurityContextHolder

object ClientExtractor {

    fun extractClient(): Client {
        val principal = SecurityContextHolder
            .getContext()
            ?.authentication
            ?.principal

        return if (principal is KeycloakPrincipal<*>) {
            when (principal.keycloakSecurityContext.token.issuedFor) {
                "teachers" -> Client.Teachers
                "hq" -> Client.Hq
                "boclips-web-app" -> Client.BoclipsWebApp
                else -> Client.UnknownClient
            }
        } else Client.UnknownClient
    }
}