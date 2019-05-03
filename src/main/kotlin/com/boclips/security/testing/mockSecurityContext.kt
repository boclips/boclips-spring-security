package com.boclips.security.testing

import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.User

fun setSecurityContext(username: String) {
    SecurityContextHolder
        .setContext(
            SecurityContextImpl(
                TestingAuthenticationToken(username, null)
            )
        )
}

fun setSecurityContext(username: String, vararg roles: String) {
    SecurityContextHolder
        .setContext(
            SecurityContextImpl(
                TestingAuthenticationToken(User(username, "", roles.map { SimpleGrantedAuthority("ROLE_$it") }), null)
            )
        )
}