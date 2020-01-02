package com.boclips.security.testing

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class FakeAuthorizationFilter : OncePerRequestFilter() {
    @Throws(IOException::class, ServletException::class)
    override fun doFilterInternal(req: HttpServletRequest, res: HttpServletResponse, chain: FilterChain) {
        val header = req.getHeader("Authorization")
        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            val token = header.replace(TOKEN_PREFIX, "")
            SecurityContextHolder.getContext().authentication = FakeTokenHelper().extractFromJwtToken(token)
        }
        chain.doFilter(req, res)
    }

    companion object {
        private const val TOKEN_PREFIX = "Bearer "
    }
}
