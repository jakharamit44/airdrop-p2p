package com.airdrop.p2p.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import ds.tokens.DsDarkColors
import ds.tokens.DsLightColors
import ds.tokens.LocalDsColors

private val DarkColorScheme = darkColorScheme(
    primary = AppDarkColors.bgActionPrimary,
    onPrimary = AppDarkColors.textOnAction,
    secondary = AppDarkColors.bgAccentSubtle,
    onSecondary = AppDarkColors.textAccent,
    background = AppDarkColors.surfaceBase,
    onBackground = AppDarkColors.textPrimary,
    surface = AppDarkColors.surfaceRaised,
    onSurface = AppDarkColors.textPrimary
)

private val LightColorScheme = lightColorScheme(
    primary = AppLightColors.bgActionPrimary,
    onPrimary = AppLightColors.textOnAction,
    secondary = AppLightColors.bgAccentSubtle,
    onSecondary = AppLightColors.textAccent,
    background = AppLightColors.surfaceBase,
    onBackground = AppLightColors.textPrimary,
    surface = AppLightColors.surfaceRaised,
    onSurface = AppLightColors.textPrimary
)

@Composable
fun AirDropTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {
    val dsColors = if (darkTheme) DsDarkColors else DsLightColors
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    CompositionLocalProvider(LocalDsColors provides dsColors) {
        MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
    }
}
