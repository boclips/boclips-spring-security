package com.boclips.security.testing

import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.lang.Exception
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtHelper {
    fun extractFromJwtToken(token: String): Authentication? {
        return try {
            val (email, rolesStr) = token.split('|')
            val roles = rolesStr.split(",").toTypedArray()
            TestingAuthenticationToken(email, null, *roles)
                .apply {
                    isAuthenticated = true
                }
        } catch (ex: Exception) {
            null
        }
    }

    fun createToken(username: String, vararg roles: String): String {
        return username + "|" + roles.joinToString(separator = ",")
    }
}

class FakeAuthorizationFilter : OncePerRequestFilter() {
    @Throws(IOException::class, ServletException::class)
    override fun doFilterInternal(req: HttpServletRequest, res: HttpServletResponse, chain: FilterChain) {
        val header = req.getHeader("Authorization")
        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            val token = header.replace(TOKEN_PREFIX, "")
            SecurityContextHolder.getContext().authentication = JwtHelper().extractFromJwtToken(token)
        }
        chain.doFilter(req, res)
    }

    companion object {
        private const val TOKEN_PREFIX = "Bearer "
    }
}
