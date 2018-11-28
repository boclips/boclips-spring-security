package com.boclips.security.utils

import com.sun.security.auth.UserPrincipal
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl

internal class UserExtractorTest {
    val boclipsUsername = "test@boclips.com"
    val boclipsUserId = "user-id"

    @Test
    fun `when principal extracts mail from name`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(UserPrincipal(boclipsUsername))

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User.fromEmail(boclipsUsername, boclipsUsername))
    }

    @Test
    fun `when userDetails extracts mail from username`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(org.springframework.security.core.userdetails.User(boclipsUsername, "password", emptyList()))

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User.fromEmail(boclipsUsername, boclipsUsername))
    }

    @Test
    fun `when string extracts mail from value`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(boclipsUsername)

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User.fromEmail(boclipsUsername, boclipsUsername))
    }

    @Test
    fun `when keycloak principal extracts preferredUsername`() {
        val keycloakPrincipal = KeycloakPrincipal(boclipsUserId, KeycloakSecurityContext(null, AccessToken().apply { preferredUsername = boclipsUsername }, null, null))
        setSecurityContext(keycloakPrincipal)

        assertThat(UserExtractor.getCurrentUser()).isEqualTo(User.fromEmail(boclipsUsername, boclipsUserId))
    }

    @Test
    fun `when there is no user in current context`() {
        setSecurityContext(null)
        assertThat(UserExtractor.getCurrentUser()).isNull()

        setSecurityContext(SecurityContextImpl(null))
        assertThat(UserExtractor.getCurrentUser()).isNull()

        SecurityContextHolder.setContext(null)
        assertThat(UserExtractor.getCurrentUser()).isNull()
    }

    fun setSecurityContext(authenticatedUser: Any?) {
        SecurityContextHolder.setContext(SecurityContextImpl(TestingAuthenticationToken(authenticatedUser, null)))
    }
}