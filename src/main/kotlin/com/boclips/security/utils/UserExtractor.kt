package com.boclips.security.utils

import org.keycloak.KeycloakPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import java.security.Principal

object UserExtractor {
    fun getCurrentUser(): User? {
        val user = SecurityContextHolder.getContext()?.authentication?.principal

        return when (user) {
            is KeycloakPrincipal<*> -> {
                val email = user.keycloakSecurityContext.token.preferredUsername
                val authorities = user.keycloakSecurityContext.token.realmAccess?.let { it.roles } ?: emptySet<String>()

                User(boclipsEmployee = isBoclipsEmployee(email), id = user.name, authorities = authorities)
            }
            is Principal ->
                User(
                    boclipsEmployee = isBoclipsEmployee(user.name),
                    id = user.name,
                    authorities = emptySet()
                )
            is UserDetails ->
                User(
                    boclipsEmployee = isBoclipsEmployee(user.username),
                    id = user.username,
                    authorities = user.authorities.map { it.authority }.toSet()
                )
            is String ->
                User(
                    boclipsEmployee = isBoclipsEmployee(user),
                    id = user,
                    authorities = emptySet()
                )
            else -> null
        }
    }

    private fun isBoclipsEmployee(email: String) =
        email.endsWith("@boclips.com")
}