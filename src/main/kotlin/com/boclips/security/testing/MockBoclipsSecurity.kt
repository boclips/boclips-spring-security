package com.boclips.security.testing

import org.springframework.context.annotation.Import
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FILE)
@Import(SecurityConfigFake::class)
@EnableWebSecurity
annotation class MockBoclipsSecurity