package io.github.jakharamit44.glidedrop.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import ds.tokens.DsDarkColors
import ds.tokens.DsLightColors
import ds.tokens.LocalDsColors

private val DarkColorScheme = darkColorScheme(
    primary = DsDarkColors.bgActionPrimary,
    onPrimary = DsDarkColors.textOnAction,
    primaryContainer = DsDarkColors.bgAccentSubtle,
    onPrimaryContainer = DsDarkColors.textPrimary,
    secondary = DsDarkColors.bgSuccessBold,
    onSecondary = DsDarkColors.textOnSuccess,
    secondaryContainer = DsDarkColors.bgSuccessSubtle,
    onSecondaryContainer = DsDarkColors.textPrimary,
    background = DsDarkColors.surfaceBase,
    onBackground = DsDarkColors.textPrimary,
    surface = DsDarkColors.surfaceRaised,
    onSurface = DsDarkColors.textPrimary,
    surfaceVariant = DsDarkColors.surfaceSunken,
    onSurfaceVariant = DsDarkColors.textSecondary,
    surfaceContainerLowest = DsDarkColors.surfaceBase,
    surfaceContainerLow = DsDarkColors.surfaceSunken,
    surfaceContainer = DsDarkColors.surfaceRaised,
    surfaceContainerHigh = DsDarkColors.surfaceOverlay,
    surfaceContainerHighest = DsDarkColors.bgNeutralSubtle,
    outline = DsDarkColors.borderDefault,
    outlineVariant = DsDarkColors.borderSubtle,
    error = DsDarkColors.textDanger,
    onError = DsDarkColors.surfaceBase
)

private val LightColorScheme = lightColorScheme(
    primary = DsLightColors.bgActionPrimary,
    onPrimary = DsLightColors.textOnAction,
    primaryContainer = DsLightColors.bgAccentSubtle,
    onPrimaryContainer = DsLightColors.textPrimary,
    secondary = DsLightColors.bgSuccessBold,
    onSecondary = DsLightColors.textOnSuccess,
    secondaryContainer = DsLightColors.bgSuccessSubtle,
    onSecondaryContainer = DsLightColors.textPrimary,
    background = DsLightColors.surfaceBase,
    onBackground = DsLightColors.textPrimary,
    surface = DsLightColors.surfaceRaised,
    onSurface = DsLightColors.textPrimary,
    surfaceVariant = DsLightColors.surfaceSunken,
    onSurfaceVariant = DsLightColors.textSecondary,
    surfaceContainerLowest = DsLightColors.surfaceBase,
    surfaceContainerLow = DsLightColors.surfaceSunken,
    surfaceContainer = DsLightColors.surfaceRaised,
    surfaceContainerHigh = DsLightColors.surfaceOverlay,
    surfaceContainerHighest = DsLightColors.bgNeutralSubtle,
    outline = DsLightColors.borderDefault,
    outlineVariant = DsLightColors.borderSubtle,
    error = DsLightColors.textDanger,
    onError = DsLightColors.surfaceBase
)

@Composable
fun GlideDropTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {
    val dsColors = if (darkTheme) DsDarkColors else DsLightColors
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = !darkTheme
            controller.isAppearanceLightNavigationBars = !darkTheme
        }
    }
    CompositionLocalProvider(LocalDsColors provides dsColors) {
        MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
    }
}
