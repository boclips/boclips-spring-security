package com.boclips.security.utils

import com.boclips.security.testsupport.SecurityContextHelper.setKeycloakSecurityContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.ArgumentsProvider
import org.junit.jupiter.params.provider.ArgumentsSource
import java.util.stream.Stream

class ClientExtractorTest {

    @ParameterizedTest
    @ArgumentsSource(ClientExtractorArgumentProvider::class)
    fun `should extract correct client from the token`(issuedFor: String?, expectedClient: Client) {
        setKeycloakSecurityContext(
            id = "my-user-id",
            userName = "test@noclips.com",
            issuedForClaim = issuedFor
        )

        assertThat(ClientExtractor.extractClient()).isEqualTo(expectedClient)
    }

    internal class ClientExtractorArgumentProvider: ArgumentsProvider {
        override fun provideArguments(context: ExtensionContext?): Stream<out Arguments> {
            return Stream.of(
                Arguments.of("teachers", Client.Teachers),
                Arguments.of("hq", Client.Hq),
                Arguments.of("boclips-web-app", Client.BoclipsWebApp),
                Arguments.of("random", Client.UnknownClient),
                Arguments.of("", Client.UnknownClient),
                Arguments.of(null, Client.UnknownClient),
            )
        }
    }
}