package com.boclips.security.testing

import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

class FakeTokenHelper {
    fun extractFromJwtToken(token: String): Authentication? {
        return try {
            val (email, rolesStr) = token.split('|')
            val roles = rolesStr.split(",").filter { it.isNotEmpty() }.toTypedArray()
            val user = User(email, "password", roles.map { SimpleGrantedAuthority(it) })
            TestingAuthenticationToken(user, null, *roles)
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
        return if (role.startsWith("ROLE_")) role else "ROLE_$role"
    }
}
