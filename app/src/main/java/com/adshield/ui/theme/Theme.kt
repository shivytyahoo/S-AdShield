package com.adshield.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * S-AdShield dark theme. Every color lives here as a Material 3
 * colorScheme token; call sites use MaterialTheme.colorScheme only.
 */
private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF59E1B8),
    onPrimary = Color(0xFF08111F),
    secondary = Color(0xFFFFB84D),
    onSecondary = Color(0xFF08111F),
    background = Color(0xFF08111F),
    onBackground = Color(0xFFF4F7FB),
    surface = Color(0xFF101C2E),
    onSurface = Color(0xFFF4F7FB),
    surfaceVariant = Color(0xFF16352F),
    onSurfaceVariant = Color(0xFF93A4BA),
    outline = Color(0xFF60738B),
    outlineVariant = Color(0xFF22344A),
    error = Color(0xFFFF6B7A),
    onError = Color(0xFF08111F)
)

@Composable
fun AdShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
