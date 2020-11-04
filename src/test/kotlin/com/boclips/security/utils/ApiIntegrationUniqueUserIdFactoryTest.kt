package com.boclips.security.utils

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.keycloak.representations.AccessToken

class ApiIntegrationUniqueUserIdFactoryTest {

    @Test
    fun `should create a unique user ID if both clientId and boclips_user_id claims are specified`() {
        val clientId = "some-integration"
        val boclipsUserId = "some-boclip-user-id"

        val accessToken = AccessToken().apply {
            this.otherClaims.putAll(mapOf(
                    "clientId" to clientId,
                    "boclips_user_id" to boclipsUserId
            ))
        }

        val result = ApiIntegrationUniqueUserIdFactory.create(accessToken)

        assertThat(result).isEqualTo("some-integration_some-boclip-user-id")
    }

    @Test
    fun `should return null if clientId claim is not specified`() {
        val clientId = null
        val boclipsUserId = "some-boclip-user-id"

        val accessToken = AccessToken().apply {
            this.otherClaims.putAll(mapOf(
                    "clientId" to clientId,
                    "boclips_user_id" to boclipsUserId
            ))
        }

        val result = ApiIntegrationUniqueUserIdFactory.create(accessToken)

        assertThat(result).isNull()
    }

    @Test
    fun `should return null if boclips_user_id claim is not specified`() {
        val clientId = "some-integration"
        val boclipsUserId = null

        val accessToken = AccessToken().apply {
            this.otherClaims.putAll(mapOf(
                    "clientId" to clientId,
                    "boclips_user_id" to boclipsUserId
            ))
        }

        val result = ApiIntegrationUniqueUserIdFactory.create(accessToken)

        assertThat(result).isNull()
    }

    @Test
    fun `should return null if both clientId and boclips_user_id claims are not specified`() {
        val clientId = null
        val boclipsUserId = null

        val accessToken = AccessToken().apply {
            this.otherClaims.putAll(mapOf(
                    "clientId" to clientId,
                    "boclips_user_id" to boclipsUserId
            ))
        }

        val result = ApiIntegrationUniqueUserIdFactory.create(accessToken)

        assertThat(result).isNull()
    }
}
