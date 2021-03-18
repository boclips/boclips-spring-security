package com.boclips.security.utils

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.ArgumentsProvider
import org.junit.jupiter.params.provider.ArgumentsSource
import java.util.stream.Stream

class ClientTest {

    @ParameterizedTest
    @ArgumentsSource(ClientArgumentProvider::class)
    fun `should convert from name to client to name`(name: String?, client: Client) {
        val clientResult = Client.getClientByName(name)
        val nameResult = Client.getNameByClient(clientResult)

        assertThat(clientResult).isEqualTo(client)
        assertThat(nameResult).isEqualTo(name)
    }

    internal class ClientArgumentProvider: ArgumentsProvider {
        override fun provideArguments(context: ExtensionContext?): Stream<out Arguments> {
            return Stream.of(
                Arguments.of("teachers", Client.Teachers),
                Arguments.of("hq", Client.Hq),
                Arguments.of("boclips-web-app", Client.BoclipsWebApp),
                Arguments.of(null, Client.UnknownClient),
            )
        }
    }
}