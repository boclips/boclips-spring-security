package com.boclips.security.utils

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl

internal class UserExtractorTest {
    @Test
    fun `retrieves and identifies Boclips employees, using email as ID`() {
        setSecurityContext(org.springframework.security.core.userdetails.User("test@boclips.com", "password", emptyList()))
        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User(boclipsEmployee = true, id = "test@boclips.com"))
    }

    @Test
    fun `uses a keycloak principal's preferred username`() {
        setSecurityContext(KeycloakPrincipal(
                "my-user-id",
                KeycloakSecurityContext(
                        null,
                        AccessToken().apply { preferredUsername = "test@noclips.com" },
                        null,
                        null
                )))
        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User(boclipsEmployee = false, id = "my-user-id"))
    }

    @Test
    fun `is null when no user is in current context`() {
        setSecurityContext(null)
        assertThat(UserExtractor.getCurrentUser()).isNull()

        setSecurityContext(SecurityContextImpl(null))
        assertThat(UserExtractor.getCurrentUser()).isNull()
    }

    private fun setSecurityContext(authenticatedUser: Any?) {
        SecurityContextHolder.setContext(SecurityContextImpl(TestingAuthenticationToken(authenticatedUser, null)))
    }
}