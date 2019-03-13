package com.boclips.security.utils

data class User(
        val boclipsEmployee: Boolean,
        val id: String,
        val roles: Set<String>
) {
    fun hasRole(role: String): Boolean {
        return roles.contains(role)
    }
}