package com.boclips.security.testsupport

import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl

object SecurityContextHelper {

    fun setSecurityContext(authenticatedUser: Any?) {
        SecurityContextHolder
            .setContext(SecurityContextImpl(TestingAuthenticationToken(authenticatedUser, null)))
    }

    fun setKeycloakSecurityContext(
        id: String,
        userName: String = "$id@noclips.com",
        roles: Array<String> = emptyArray(),
        serviceRoles: Map<String, String> = emptyMap(),
        otherClaims: Map<String, String> = emptyMap(),
        issuedForClaim: String? = ""
    ) {
        setSecurityContext(
            KeycloakPrincipal(
                id,
                KeycloakSecurityContext(
                    null,
                    AccessToken().apply {
                        preferredUsername = userName
                        realmAccess = AccessToken
                            .Access()
                            .apply {
                                roles
                                    .forEach {
                                        this
                                            .addRole(it)
                                    }
                            }
                        resourceAccess = serviceRoles
                            .mapValues {
                                AccessToken
                                    .Access()
                                    .addRole(it.value)
                            }
                        issuedFor = issuedForClaim
                        this.otherClaims.putAll(otherClaims)
                    },
                    null,
                    null
                )
            )
        )
    }
}