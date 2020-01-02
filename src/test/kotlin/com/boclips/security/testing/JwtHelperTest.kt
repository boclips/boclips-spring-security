package com.boclips.security.testing

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtHelperTest {
    @Test
    fun `extract authentication from token`() {
        val jwtHelper = JwtHelper()

        val authentication = jwtHelper
            .extractFromJwtToken(jwtHelper.createToken("some-user", "ROLE_TEST", "ROLE_BEST"))

        assertThat(authentication!!.principal).isEqualTo("some-user")
        assertThat(authentication.authorities.map { it.authority }).containsExactly("ROLE_TEST", "ROLE_BEST")
    }

    @Test
    fun `ignores authentication headers in unknown format`() {
        val jwtHelper = JwtHelper()

        val authentication = jwtHelper.extractFromJwtToken("a real token")

        assertThat(authentication).isNull()
    }
}
