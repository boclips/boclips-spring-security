package com.boclips.security

import org.springframework.security.config.annotation.web.builders.HttpSecurity

interface HttpSecurityConfigurer {
    fun configure(http: HttpSecurity)
}