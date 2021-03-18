package com.boclips.security.utils

sealed class Client {
    object Teachers : Client()
    object BoclipsWebApp : Client()
    object Hq : Client()
    object UnknownClient : Client()

    companion object {
        fun getClientByName(name: String?) =
            when (name) {
                "teachers" -> Teachers
                "hq" -> Hq
                "boclips-web-app" -> BoclipsWebApp
                else -> UnknownClient
            }

        fun getNameByClient(client: Client): String? =
            when (client) {
                Teachers -> "teachers"
                Hq -> "hq"
                BoclipsWebApp -> "boclips-web-app"
                else -> null
            }
    }
}