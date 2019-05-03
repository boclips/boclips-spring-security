package com.boclips.security.utils

data class User(
    val boclipsEmployee: Boolean,
    val id: String,
    private val authorities: Set<String>
) {

    fun hasRole(role: String): Boolean {
        return authorities.contains("ROLE_$role")
    }

    fun hasAuthority(authority: String): Boolean {
        return authorities.contains(authority)
    }
}

fun User?.hasRole(role: String): Boolean = this?.hasRole(role) ?: false
fun User?.hasAuthority(authority: String): Boolean = this?.hasAuthority(authority) ?: false