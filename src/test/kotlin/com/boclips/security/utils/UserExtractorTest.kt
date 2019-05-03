package com.boclips.security.utils

import com.sun.security.auth.UserPrincipal
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl

internal class UserExtractorTest {
    @Test
    fun `retrieves and identifies Boclips employees, using email as ID`() {
        setSecurityContext(
            org.springframework.security.core.userdetails.User(
                "test@boclips.com",
                "password",
                emptyList()
            )
        )

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(
            User(
                boclipsEmployee = true,
                id = "test@boclips.com",
                authorities = emptySet()
            )
        )
    }

    @Test
    fun `when principal extracts mail from name`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(UserPrincipal(boclipsUsername))

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(
            User(
                boclipsEmployee = true,
                id = "test@boclips.com",
                authorities = emptySet()
            )
        )
    }

    @Test
    fun `when string extracts mail from value`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(boclipsUsername)

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(
            User(
                boclipsEmployee = true,
                id = "test@boclips.com",
                authorities = emptySet()
            )
        )
    }

    @Test
    fun `detects non-Boclips employees from Spring security`() {
        setSecurityContext(
            org.springframework.security.core.userdetails.User(
                "test@pearsonclips.com",
                "password",
                emptyList()
            )
        )

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(
            User(
                boclipsEmployee = false,
                id = "test@pearsonclips.com",
                authorities = emptySet()
            )
        )
    }

    @Test
    fun `retrieves user roles from Spring user details`() {
        setSecurityContext(
            org.springframework.security.core.userdetails.User(
                "test@boclips.com",
                "password",
                mutableListOf<GrantedAuthority>(
                    SimpleGrantedAuthority("ROLE_VEGGIESPAM"),
                    SimpleGrantedAuthority("ROLE_BEANS")
                )
            )
        )

        assertThat(UserExtractor.getCurrentUser().hasRole("VEGGIESPAM")).isTrue()
        assertThat(UserExtractor.getCurrentUser().hasRole("BEANS")).isTrue()
        assertThat(UserExtractor.getCurrentUser().hasAuthority("ROLE_VEGGIESPAM")).isTrue()
        assertThat(UserExtractor.getCurrentUser().hasAuthority("ROLE_BEANS")).isTrue()
    }

    @Test
    fun `uses a Keycloak principal's preferred username`() {
        setSecurityContext(
            KeycloakPrincipal(
                "my-user-id",
                KeycloakSecurityContext(
                    null,
                    AccessToken().apply {
                        preferredUsername = "test@noclips.com"
                    },
                    null,
                    null
                )
            )
        )

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(
            User(
                boclipsEmployee = false,
                id = "my-user-id",
                authorities = emptySet()
            )
        )
    }

    @Test
    fun `retrieves user roles from Keycloak`() {
        setSecurityContext(
            KeycloakPrincipal(
                "my-user-id",
                KeycloakSecurityContext(
                    null,
                    AccessToken().apply {
                        preferredUsername = "test@noclips.com"
                        realmAccess = AccessToken.Access().addRole("ROLE_GARBAGE")
                    },
                    null,
                    null
                )
            )
        )

        assertThat(UserExtractor.getCurrentUser().hasRole("GARBAGE")).isTrue()
        assertThat(UserExtractor.getCurrentUser().hasRole("RUBBISH")).isFalse()
        assertThat(UserExtractor.getCurrentUser().hasAuthority("ROLE_GARBAGE")).isTrue()
        assertThat(UserExtractor.getCurrentUser().hasAuthority("ROLE_RUBBISH")).isFalse()
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