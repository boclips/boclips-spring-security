package com.boclips.security.utils

import org.keycloak.representations.AccessToken

object ApiIntegrationUniqueUserIdFactory {

    private const val CLIENT_ID_CLAIM = "clientId"
    private const val BOCLIPS_USER_ID_CLAIM = "boclips_user_id"

    fun create(accessToken: AccessToken): String? {
        val boclipsUserId = accessToken.otherClaims[BOCLIPS_USER_ID_CLAIM] as String?
        val clientId = accessToken.otherClaims[CLIENT_ID_CLAIM] as String?
        return if (boclipsUserId != null && clientId != null) {
            "${clientId}_${boclipsUserId}"
        } else {
            null
        }
    }
}
