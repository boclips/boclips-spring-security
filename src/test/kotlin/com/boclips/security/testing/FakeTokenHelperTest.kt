package com.boclips.security.testing

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class FakeTokenHelperTest {
    @Test
    fun `extract authentication from token`() {
        val jwtHelper = FakeTokenHelper()

        val authentication = jwtHelper
            .extractFromJwtToken(jwtHelper.createToken("some-user", "ROLE_TEST", "ROLE_BEST"))

        assertThat((authentication!!.principal as UserDetails).username).isEqualTo("some-user")
        assertThat((authentication.principal as UserDetails).authorities.map { it.toString() }).containsExactlyInAnyOrder(
            "ROLE_TEST",
            "ROLE_BEST"
        )
    }

    @Test
    fun `authenticates user when no roles present`() {
        val jwtHelper = FakeTokenHelper()

        val authentication = jwtHelper.extractFromJwtToken("user|")

        assertThat((authentication!!.principal as UserDetails).username).isEqualTo("user")
        assertThat((authentication.principal as UserDetails).authorities).isEmpty()
    }

    @Test
    fun `add role prefix when not present`() {
        val jwtHelper = FakeTokenHelper()

        val authentication = jwtHelper.extractFromJwtToken(jwtHelper.createToken("user", "LONDON"))

        assertThat((authentication!!.principal as UserDetails).authorities)
            .containsExactly(SimpleGrantedAuthority("ROLE_LONDON"))
    }

    @Test
    fun `ignores authentication headers in unknown format`() {
        val jwtHelper = FakeTokenHelper()

        val authentication = jwtHelper.extractFromJwtToken("a real token")

        assertThat(authentication).isNull()
    }
}
