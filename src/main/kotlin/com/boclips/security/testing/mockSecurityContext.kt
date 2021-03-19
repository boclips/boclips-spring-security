package com.boclips.security.testing

import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.User

fun setSecurityContext(username: String) {
    SecurityContextHolder
        .setContext(
            SecurityContextImpl(
                TestingAuthenticationToken(username, null)
            )
        )
}

fun setSecurityContext(username: String, vararg roles: String) {
    SecurityContextHolder
        .setContext(
            SecurityContextImpl(
                TestingAuthenticationToken(User(username, "", roles.map { SimpleGrantedAuthority("ROLE_$it") }), null)
            )
        )
}

fun setSecurityContext(userId: String, clientId: String) {
    SecurityContextHolder
        .setContext(SecurityContextImpl(TestingAuthenticationToken(
            KeycloakPrincipal(
            userId,
            KeycloakSecurityContext(
                null,
                AccessToken().apply {
                    preferredUsername = "$id@noclips.com"
                    realmAccess = AccessToken
                        .Access()
                    resourceAccess = emptyMap<String, String>()
                        .mapValues {
                            AccessToken
                                .Access()
                                .addRole(it.value)
                        }
                    issuedFor = clientId
                    this.otherClaims.putAll(otherClaims)
                },
                null,
                null
            )
        ), null)))
}