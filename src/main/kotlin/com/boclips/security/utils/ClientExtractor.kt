package com.boclips.security.utils

import org.keycloak.KeycloakPrincipal
import org.springframework.security.core.context.SecurityContextHolder

object ClientExtractor {

    fun extractClient(): Client {
        val principal = SecurityContextHolder
            .getContext()
            ?.authentication
            ?.principal

        return when(principal) {
            is KeycloakPrincipal<*> -> Client.getClientByName(principal.keycloakSecurityContext.token.issuedFor)
            else -> Client.UnknownClient
        }
    }
}