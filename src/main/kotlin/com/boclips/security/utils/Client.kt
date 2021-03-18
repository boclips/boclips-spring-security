package com.boclips.security.utils

sealed class Client {
    object Teachers : Client()
    object BoclipsWebApp : Client()
    object Hq : Client()
    object UnknownClient : Client()
}