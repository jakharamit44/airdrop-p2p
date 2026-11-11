package io.github.jakharamit44.glidedrop.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import ds.tokens.DsDarkColors
import ds.tokens.DsLightColors
import ds.tokens.LocalDsColors

private val DarkColorScheme = darkColorScheme(
    primary = DsDarkColors.bgActionPrimary,
    onPrimary = DsDarkColors.textOnAction,
    secondary = DsDarkColors.bgAccentSubtle,
    onSecondary = DsDarkColors.textAccent,
    background = DsDarkColors.surfaceBase,
    onBackground = DsDarkColors.textPrimary,
    surface = DsDarkColors.surfaceRaised,
    onSurface = DsDarkColors.textPrimary
)

private val LightColorScheme = lightColorScheme(
    primary = DsLightColors.bgActionPrimary,
    onPrimary = DsLightColors.textOnAction,
    secondary = DsLightColors.bgAccentSubtle,
    onSecondary = DsLightColors.textAccent,
    background = DsLightColors.surfaceBase,
    onBackground = DsLightColors.textPrimary,
    surface = DsLightColors.surfaceRaised,
    onSurface = DsLightColors.textPrimary
)

@Composable
fun GlideDropTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {
    val dsColors = if (darkTheme) DsDarkColors else DsLightColors
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    CompositionLocalProvider(LocalDsColors provides dsColors) {
        MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
    }
}
