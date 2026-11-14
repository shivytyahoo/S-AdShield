package com.adshield.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import shivyt.android.adshield.R

/** Snapshot of everything the dashboard shows; the activity refreshes it. */
data class DashboardState(
    val enabled: Boolean = false,
    val queries: Long = 0,
    val blocked: Long = 0,
    val blockRate: Int = 0,
    val streamingOn: Boolean = true,
    val antiDetectOn: Boolean = true,
    val batteryExempt: Boolean = false,
    val showMigrationNote: Boolean = false
)

@Composable
fun DashboardScreen(
    state: DashboardState,
    onToggleProtection: () -> Unit,
    onToggleStreaming: () -> Unit,
    onToggleAntiDetect: () -> Unit,
    onOpenBatterySettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 22.dp)
            .verticalScroll(rememberScrollState())
    ) {
            Spacer(Modifier.height(18.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(R.string.brand),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.weight(1f)
                )
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    Text(
                        text = stringResource(R.string.local_private),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 11.dp, vertical = 7.dp)
                    )
                }
            }
            Spacer(Modifier.height(12.dp))

            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                shape = MaterialTheme.shapes.extraLarge,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(18.dp, 24.dp, 18.dp, 24.dp)
                ) {
                    ShieldMark(enabled = state.enabled)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = stringResource(
                            if (state.enabled) R.string.protection_active
                            else R.string.protection_off
                        ),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.Center
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.protection_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                    Spacer(Modifier.height(18.dp))
                    Button(
                        onClick = onToggleProtection,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (state.enabled) {
                                MaterialTheme.colorScheme.error
                            } else {
                                MaterialTheme.colorScheme.primary
                            },
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        ),
                        modifier = Modifier.fillMaxWidth().height(56.dp)
                    ) {
                        Text(
                            text = stringResource(
                                if (state.enabled) R.string.stop_protection
                                else R.string.start_protection
                            ),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    OutlinedButton(
                        onClick = onOpenBatterySettings,
                        enabled = !state.batteryExempt,
                        modifier = Modifier.fillMaxWidth().height(42.dp)
                    ) {
                        Text(
                            text = stringResource(
                                if (state.batteryExempt) R.string.battery_ready
                                else R.string.battery_action
                            ),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
            Spacer(Modifier.height(14.dp))

            Text(
                text = stringResource(R.string.live_overview),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                StatCard(
                    label = stringResource(R.string.queries),
                    value = compact(state.queries),
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    label = stringResource(R.string.blocked),
                    value = compact(state.blocked),
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    label = stringResource(R.string.block_rate),
                    value = "${state.blockRate}%",
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(14.dp))

            ToggleCard(
                title = stringResource(R.string.streaming_title),
                subtitle = stringResource(
                    if (state.streamingOn) R.string.streaming_on else R.string.streaming_off
                ),
                checked = state.streamingOn,
                onCheckedChange = { onToggleStreaming() }
            )
            Spacer(Modifier.height(8.dp))
            ToggleCard(
                title = stringResource(R.string.antidetect_title),
                subtitle = stringResource(
                    if (state.antiDetectOn) R.string.antidetect_on else R.string.antidetect_off
                ),
                checked = state.antiDetectOn,
                onCheckedChange = { onToggleAntiDetect() }
            )
            Spacer(Modifier.height(14.dp))

            InfoCard(
                title = stringResource(R.string.engine_title),
                headline = stringResource(R.string.engine_headline),
                detail = stringResource(R.string.engine_detail)
            )
            Spacer(Modifier.height(10.dp))
            InfoCard(
                title = stringResource(R.string.sources_title),
                headline = stringResource(R.string.sources_headline),
                detail = stringResource(R.string.sources_detail)
            )
            if (state.showMigrationNote) {
                Spacer(Modifier.height(10.dp))
                InfoCard(
                    title = stringResource(R.string.migration_title),
                    headline = stringResource(R.string.migration_headline),
                    detail = stringResource(R.string.migration_text)
                )
            }
            Spacer(Modifier.height(18.dp))
            Text(
                text = stringResource(R.string.footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(28.dp))
    }
}

/** The shield glyph, gently pulsing while protection is on. */
@Composable
private fun ShieldMark(enabled: Boolean) {
    val transition = rememberInfiniteTransition(label = "shieldPulse")
    val pulseAlpha by transition.animateFloat(
        initialValue = 1f,
        targetValue = 0.55f,
        animationSpec = infiniteRepeatable(
            animation = tween(800),
            repeatMode = RepeatMode.Reverse
        ),
        label = "shieldAlpha"
    )
    Text(
        text = "◈",
        fontSize = 54.sp,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .size(92.dp)
            .alpha(if (enabled) pulseAlpha else 1f),
        textAlign = TextAlign.Center
    )
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(14.dp, 15.dp, 14.dp, 14.dp)) {
            Text(
                text = value,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ToggleCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(16.dp, 14.dp, 16.dp, 14.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

@Composable
private fun InfoCard(title: String, headline: String, detail: String) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp, 14.dp, 16.dp, 14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(5.dp))
            Text(
                text = headline,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun compact(v: Long): String = when {
    v >= 1_000_000 -> "%.1fM".format(v / 1_000_000.0)
    v >= 1_000 -> "%.1fK".format(v / 1_000.0)
    else -> v.toString()
}
