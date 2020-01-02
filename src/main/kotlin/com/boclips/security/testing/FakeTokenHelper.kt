package com.boclips.security.testing

import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import java.lang.Exception

class FakeTokenHelper {
    fun extractFromJwtToken(token: String): Authentication? {
        return try {
            val (email, rolesStr) = token.split('|')
            val roles = rolesStr.split(",").filter { it.isNotEmpty() }.toTypedArray()
            TestingAuthenticationToken(email, null, *roles)
                .apply {
                    isAuthenticated = true
                }
        } catch (ex: Exception) {
            null
        }
    }

    fun createToken(username: String, vararg roles: String): String {
        return username + "|" + roles.joinToString(separator = ",", transform = this::addRolePrefixIfMissing)
    }

    private fun addRolePrefixIfMissing(role: String): String {
        return if(role.startsWith("ROLE_")) role else "ROLE_$role"
    }
}
