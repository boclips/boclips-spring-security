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

        val currentUser = UserExtractor.getCurrentUser()

        assertThat(currentUser.hasRole("VEGGIESPAM")).isTrue()
        assertThat(currentUser.hasRole("BEANS")).isTrue()
        assertThat(currentUser.hasAuthority("ROLE_VEGGIESPAM")).isTrue()
        assertThat(currentUser.hasAuthority("ROLE_BEANS")).isTrue()
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

        val currentUser = UserExtractor.getCurrentUser()

        assertThat(currentUser.hasRole("GARBAGE")).isFalse()
        assertThat(currentUser.hasAuthority("ROLE_GARBAGE")).isFalse()
    }

    @Test
    fun `retrieves resource_access roles from Keycloak`() {
        setSecurityContext(
            KeycloakPrincipal(
                "my-user-id",
                KeycloakSecurityContext(
                    null,
                    AccessToken().apply {
                        preferredUsername = "test@noclips.com"
                        realmAccess = AccessToken.Access().addRole("GARBAGE")
                        resourceAccess = mapOf(Pair("my-service", AccessToken.Access().addRole("ROLE_MY_SERVICE_GARBAGE")))
                    },
                    null,
                    null
                )
            )
        )

        val currentUser = UserExtractor.getCurrentUser()

        assertThat(currentUser.hasRole("MY_SERVICE_GARBAGE")).isTrue()
        assertThat(currentUser.hasAuthority("ROLE_MY_SERVICE_GARBAGE")).isTrue()
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