// GlideDrop design tokens for Jetpack Compose.
package ds.tokens

import androidx.compose.animation.core.spring
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

@Immutable
data class DsColors(
    val bgAccentSubtle: Color,
    val bgActionPrimary: Color,
    val bgDisabled: Color,
    val bgNeutralSubtle: Color,
    val bgSuccessBold: Color,
    val bgSuccessSubtle: Color,
    val bgWarningSubtle: Color,
    val borderAccent: Color,
    val borderDefault: Color,
    val borderSeparator: Color,
    val borderSubtle: Color,
    val borderWarning: Color,
    val iconAccent: Color,
    val iconDefault: Color,
    val iconSubtle: Color,
    val surfaceBase: Color,
    val surfaceNav: Color,
    val surfaceOverlay: Color,
    val surfaceRaised: Color,
    val surfaceSunken: Color,
    val textAccent: Color,
    val textDanger: Color,
    val textDisabled: Color,
    val textOnAction: Color,
    val textOnSuccess: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textSuccess: Color,
    val textTertiary: Color,
    val textWarning: Color,
)

val DsLightColors = DsColors(
    bgAccentSubtle = Color(0xFFE9ECFF),
    bgActionPrimary = Color(0xFF5360F5),
    bgDisabled = Color(0xFFE5E9F2),
    bgNeutralSubtle = Color(0xFFEBEFF8),
    bgSuccessBold = Color(0xFF16A34A),
    bgSuccessSubtle = Color(0xFFDCFCE7),
    bgWarningSubtle = Color(0xFFFEF3C7),
    borderAccent = Color(0xFF6B77FA),
    borderDefault = Color(0xFFD5DCEB),
    borderSeparator = Color(0xFFE4E9F4),
    borderSubtle = Color(0xFFE4E9F4),
    borderWarning = Color(0xFFF59E0B),
    iconAccent = Color(0xFF4754E8),
    iconDefault = Color(0xFF4A5268),
    iconSubtle = Color(0xFF64708A),
    surfaceBase = Color(0xFFF3F5FC),
    surfaceNav = Color(0xFFFFFFFF),
    surfaceOverlay = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFFFFFFF),
    surfaceSunken = Color(0xFFECEFF8),
    textAccent = Color(0xFF424EE0),
    textDanger = Color(0xFFB91C1C),
    textDisabled = Color(0xFF8B95AC),
    textOnAction = Color(0xFFFFFFFF),
    textOnSuccess = Color(0xFFFFFFFF),
    textPrimary = Color(0xFF121624),
    textSecondary = Color(0xFF485168),
    textSuccess = Color(0xFF15803D),
    textTertiary = Color(0xFF636E88),
    textWarning = Color(0xFF92400E),
)

val DsDarkColors = DsColors(
    bgAccentSubtle = Color(0xFF1E2442),
    bgActionPrimary = Color(0xFF5D6AF8),
    bgDisabled = Color(0xFF222838),
    bgNeutralSubtle = Color(0xFF212738),
    bgSuccessBold = Color(0xFF16A34A),
    bgSuccessSubtle = Color(0xFF132C20),
    bgWarningSubtle = Color(0xFF2F2412),
    borderAccent = Color(0xFF6C78FF),
    borderDefault = Color(0xFF2D354B),
    borderSeparator = Color(0xFF22283A),
    borderSubtle = Color(0xFF242B3E),
    borderWarning = Color(0xFFF59E0B),
    iconAccent = Color(0xFF8C97FF),
    iconDefault = Color(0xFFB0BAD0),
    iconSubtle = Color(0xFF8A95AE),
    surfaceBase = Color(0xFF0D1018),
    surfaceNav = Color(0xFF131723),
    surfaceOverlay = Color(0xFF1B2130),
    surfaceRaised = Color(0xFF161B27),
    surfaceSunken = Color(0xFF111520),
    textAccent = Color(0xFF939EFF),
    textDanger = Color(0xFFFCA5A5),
    textDisabled = Color(0xFF69748E),
    textOnAction = Color(0xFFFFFFFF),
    textOnSuccess = Color(0xFFFFFFFF),
    textPrimary = Color(0xFFF2F5FC),
    textSecondary = Color(0xFFA9B4CC),
    textSuccess = Color(0xFF4ADE80),
    textTertiary = Color(0xFF8692AE),
    textWarning = Color(0xFFFCD34D),
)

val LocalDsColors = staticCompositionLocalOf { DsLightColors }

val DsTextFamily: FontFamily = FontFamily.Default

object DsType {
    val bodyLg = TextStyle(fontFamily = DsTextFamily, fontSize = 17.sp, lineHeight = 24.sp, fontWeight = FontWeight(400), letterSpacing = 0.em)
    val bodyMd = TextStyle(fontFamily = DsTextFamily, fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight(400), letterSpacing = 0.em)
    val bodySm = TextStyle(fontFamily = DsTextFamily, fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight(400), letterSpacing = 0.02.em)
    val labelLg = TextStyle(fontFamily = DsTextFamily, fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight(400), letterSpacing = 0.em)
    val labelMd = TextStyle(fontFamily = DsTextFamily, fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight(400), letterSpacing = 0.02.em)
    val labelSm = TextStyle(fontFamily = DsTextFamily, fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight(400), letterSpacing = 0.05.em)
    val titleLg = TextStyle(fontFamily = DsTextFamily, fontSize = 20.sp, lineHeight = 28.sp, fontWeight = FontWeight(600), letterSpacing = 0.em)
    val titleMd = TextStyle(fontFamily = DsTextFamily, fontSize = 17.sp, lineHeight = 24.sp, fontWeight = FontWeight(600), letterSpacing = 0.em)
    val titleSm = TextStyle(fontFamily = DsTextFamily, fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight(600), letterSpacing = 0.em)
}

object DsMotion {
    const val scalePress = 0.97f
    fun <T> springEffectsDefault() = spring<T>(dampingRatio = 1f, stiffness = 1600f)
}
