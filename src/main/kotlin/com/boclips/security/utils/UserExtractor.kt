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
                val authorities = getFlattenenedClientRoles(user) + getRealmRoles(user)

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

    fun currentUserHasRole(role: String) = getCurrentUser().hasRole(role)

    fun currentUserHasAnyRole(vararg roles: String) = roles.any { role -> getCurrentUser().hasRole(role) }

    fun <T>getIfAuthenticated(supplier: (userId: String) -> T): T? =
        getCurrentUser().takeIf { it?.id != "anonymousUser" }?.let { supplier(it.id) }

    fun <T>getIfHasRole(role: String, supplier: (userId: String) -> T): T? =
        if (currentUserHasRole(role)) getIfAuthenticated (supplier) else null


    fun <T : Any>getIfHasAnyRole(vararg roles: String, supplier: (userId: String) -> T): T? =
        roles.mapNotNull { getIfHasRole(it, supplier) }.firstOrNull()

    private fun getFlattenenedClientRoles(user: KeycloakPrincipal<*>) =
        user.keycloakSecurityContext.token.resourceAccess.orEmpty().flatMap { it.value.roles }.toSet()

    private fun getRealmRoles(user: KeycloakPrincipal<*>) =
        user.keycloakSecurityContext.token.realmAccess?.roles.orEmpty()

    private fun isBoclipsEmployee(email: String) =
        email.endsWith("@boclips.com")
}
