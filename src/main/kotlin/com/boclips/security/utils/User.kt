package com.boclips.security.utils

data class User(
        val boclipsEmployee: Boolean,
        val id: String
) {
    companion object {
        fun fromEmail(email: String, id: String) = User(boclipsEmployee = email.endsWith("@boclips.com"), id = id)
        fun anonymous() = User(boclipsEmployee = false, id = "ANONYMOUS")
    }
}