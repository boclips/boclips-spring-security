package com.boclips.security.utils

import com.nhaarman.mockito_kotlin.*
import com.sun.security.auth.UserPrincipal
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.representations.AccessToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter

class UserExtractorTest {

    @BeforeEach
    fun setUp() {
        setSecurityContext(null)
    }

    @Test
    fun `retrieves and identifies Boclips employees, using email as ID`() {
        setSecurityContext(
            org.springframework.security.core.userdetails.User(
                "test@boclips.com",
                "password",
                listOf(SimpleGrantedAuthority("SOME"), SimpleGrantedAuthority("ROLE"))
            )
        )

        assertThat(UserExtractor.getCurrentUser())
            .isEqualTo(
                User(
                    boclipsEmployee = true,
                    id = "test@boclips.com",
                    authorities = setOf("SOME", "ROLE")
                )
            )
    }

    @Test
    fun `when principal extracts mail from name`() {
        val boclipsUsername = "test@boclips.com"
        setSecurityContext(UserPrincipal(boclipsUsername))

        assertThat(UserExtractor.getCurrentUser())
            .isEqualTo(
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

        assertThat(UserExtractor.getCurrentUser())
            .isEqualTo(
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

        assertThat(UserExtractor.getCurrentUser())
            .isEqualTo(
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

        val currentUser = UserExtractor
            .getCurrentUser()

        assertThat(currentUser.hasRole("VEGGIESPAM"))
            .isTrue()
        assertThat(currentUser.hasRole("BEANS"))
            .isTrue()
        assertThat(currentUser.hasAuthority("ROLE_VEGGIESPAM"))
            .isTrue()
        assertThat(currentUser.hasAuthority("ROLE_BEANS"))
            .isTrue()
    }

    @Test
    fun `uses a Keycloak principal's preferred username`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com"
        )

        assertThat(UserExtractor.getCurrentUser())
            .isEqualTo(
                User(
                    boclipsEmployee = false,
                    id = "my-user-id",
                    authorities = emptySet()
                )
            )
    }

    @Test
    fun `retrieves resource_access roles from Keycloak`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            roles = arrayOf("GARBAGE"),
            serviceRoles = mapOf(Pair("my-service", "ROLE_MY_SERVICE_GARBAGE"))
        )

        val currentUser = UserExtractor
            .getCurrentUser()

        assertThat(currentUser.hasRole("MY_SERVICE_GARBAGE"))
            .isTrue()
        assertThat(currentUser.hasAuthority("ROLE_MY_SERVICE_GARBAGE"))
            .isTrue()
    }

    @Test
    fun `retrieves realm_access roles from Keycloak`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            roles = arrayOf("ROLE_API"),
            serviceRoles = mapOf(Pair("my-service", "ROLE_MY_SERVICE_GARBAGE"))
        )

        val currentUser = UserExtractor
            .getCurrentUser()

        assertThat(currentUser.hasRole("API"))
            .isTrue()
        assertThat(currentUser.hasAuthority("ROLE_API"))
            .isTrue()
    }

    @Test
    fun `is null when no user is in current context`() {
        setSecurityContext(null)
        assertThat(UserExtractor.getCurrentUser())
            .isNull()

        setSecurityContext(SecurityContextImpl(null))
        assertThat(UserExtractor.getCurrentUser())
            .isNull()
    }

    @Test
    fun `returns true when the currentUser has role`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            roles = arrayOf("ROLE_API")
        )

        assertThat(UserExtractor.currentUserHasRole("API"))
            .isTrue()
    }

    @Test
    fun `returns false when the currentUser has does not have role`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com"
        )

        assertThat(UserExtractor.currentUserHasRole("TEST"))
            .isFalse()
    }

    @Test
    fun `returns true when the currentUser has one of the roles`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            roles = arrayOf("ROLE_API")
        )

        assertThat(UserExtractor.currentUserHasAnyRole("API", "TEST"))
            .isTrue()
    }

    @Test
    fun `returns false when the currentUser does not have one of the roles`() {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            roles = arrayOf("ROLE_API")
        )

        assertThat(UserExtractor.currentUserHasAnyRole("ONE", "TWO"))
            .isFalse()
    }

    @Test
    fun `it does not call supplier if not authenticated`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        val result = UserExtractor
            .getIfAuthenticated(mockLambda)

        verify(mockLambda, never())
            .invoke(any())
        assertThat(result)
            .isNull()
    }

    @Test
    fun `it does call the supplier if an anonymousUser`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        setKeycloakSecurityContext(id = "anonymousUser")

        val result = UserExtractor
            .getIfAuthenticated(mockLambda)

        verify(mockLambda, never())
            .invoke(any())
        assertThat(result)
            .isNull()
    }

    @Test
    fun `it does call the supplier if authenticated`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        val boclipsUsername = "test@boclips.com"
        setKeycloakSecurityContext(id = boclipsUsername)

        val result = UserExtractor
            .getIfAuthenticated(mockLambda)

        verify(mockLambda, times(1))
            .invoke(boclipsUsername)
        assertThat(result)
            .isEqualTo(true)
    }

    @Test
    fun `it does call the supplier if the user has role`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        val boclipsId = "test-id"
        setKeycloakSecurityContext(id = boclipsId, roles = arrayOf("ROLE_ONE", "ROLE_TWO"))


        val result = UserExtractor
            .getIfHasRole("ONE", mockLambda)

        verify(mockLambda, times(1))
            .invoke(boclipsId)
        assertThat(result)
            .isEqualTo(true)
    }

    @Test
    fun `it does not call the supplier if the user does not have the role`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        setKeycloakSecurityContext(id = "test-id", roles = arrayOf("ROLE_ONE", "ROLE_TWO"))

        val result = UserExtractor
            .getIfHasRole("THREE", mockLambda)

        verify(mockLambda, never())
            .invoke(any())
        assertThat(result)
            .isNull()
    }

    @Test
    fun `it calls the supplier if the user has at least one matching role`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        val boclipsId = "test-id"
        setKeycloakSecurityContext(id = boclipsId, roles = arrayOf("ROLE_ONE", "ROLE_TWO"))


        val result = UserExtractor
            .getIfHasAnyRole("ONE", "FOUR") { mockLambda(it) }

        verify(mockLambda, times(1))
            .invoke(boclipsId)
        assertThat(result)
            .isEqualTo(true)
    }

    @Test
    fun `it does not call the supplier if the user has no matching role`() {
        val mockLambda = mock<(String) -> Boolean> {
            onGeneric { invoke(any()) } doReturn true
        }

        val boclipsId = "test-id"
        setKeycloakSecurityContext(id = boclipsId, roles = arrayOf("ROLE_ONE", "ROLE_TWO"))


        val result = UserExtractor
            .getIfHasAnyRole("THREE", "FOUR") { mockLambda(it) }

        verify(mockLambda, never())
            .invoke(any())
        assertThat(result)
            .isNull()
    }

    @Test
    fun `an anonymous user is not returned`() {
        setKeycloakSecurityContext(id = springAnonymousUser)

        val result = UserExtractor
            .getCurrentUserIfNotAnonymous()

        assertThat(result)
            .isNull()
    }

    @Test
    fun `a non-anonymous user is returned`() {
        setKeycloakSecurityContext(id = "authenticated-user")

        val result = UserExtractor
            .getCurrentUserIfNotAnonymous()

        assertThat(result)
            .isNotNull()
        assertThat(result!!.id)
            .isEqualTo("authenticated-user")
    }

    private val springAnonymousUser = AnonymousAuthenticationFilter("key")
        .principal as String

    private fun setSecurityContext(authenticatedUser: Any?) {
        SecurityContextHolder
            .setContext(SecurityContextImpl(TestingAuthenticationToken(authenticatedUser, null)))
    }

    private fun setKeycloakSecurityContext(id: String, userName: String = "$id@noclips.com", roles: Array<String> = emptyArray(), serviceRoles: Map<String, String> = emptyMap()) {
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
                    },
                    null,
                    null
                )
            )
        )
    }
}
