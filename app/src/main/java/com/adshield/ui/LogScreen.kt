package com.adshield.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.adshield.AdBlocker
import com.adshield.QueryEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import shivyt.android.adshield.R

/**
 * Request log (v1.1.0): the most recent DNS decisions, newest first.
 * Tapping Block/Allow adds a user rule for that domain, which beats
 * every built-in list.
 */
@Composable
fun LogScreen(
    entries: List<QueryEntry>,
    onClear: () -> Unit,
    onShare: () -> Unit,
    onSetRule: (String, Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 22.dp)
    ) {
        Spacer(Modifier.height(18.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.log_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = onShare) {
                Text(text = stringResource(R.string.log_share))
            }
            TextButton(onClick = onClear) {
                Text(text = stringResource(R.string.log_clear))
            }
        }
        Text(
            text = stringResource(R.string.log_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(12.dp))
        if (entries.isEmpty()) {
            Text(
                text = stringResource(R.string.log_empty),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 24.dp)
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                itemsIndexed(entries.reversed()) { _, entry ->
                    LogRow(
                        entry = entry,
                        timeText = timeFormat.format(Date(entry.timeMs)),
                        onSetRule = onSetRule
                    )
                }
            }
        }
    }
}

@Composable
private fun LogRow(
    entry: QueryEntry,
    timeText: String,
    onSetRule: (String, Int) -> Unit
) {
    val userRule = AdBlocker.userRuleFor(entry.domain)
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp, 12.dp, 14.dp, 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = entry.appLabel,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
                VerdictChip(blocked = entry.blocked)
            }
            Text(
                text = entry.domain,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = timeText,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f)
                )
                if (userRule == 1) {
                    Text(
                        text = stringResource(R.string.log_allowed_by_you),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else if (userRule == -1) {
                    Text(
                        text = stringResource(R.string.log_blocked_by_you),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                if (userRule != 0) {
                    TextButton(onClick = { onSetRule(entry.domain, 0) }) {
                        Text(text = stringResource(R.string.log_clear_rule))
                    }
                }
                TextButton(
                    onClick = {
                        onSetRule(entry.domain, if (entry.blocked) 1 else -1)
                    }
                ) {
                    Text(
                        text = stringResource(
                            if (entry.blocked) R.string.log_allow else R.string.log_block
                        )
                    )
                }
            }
        }
    }
}

@Composable
private fun VerdictChip(blocked: Boolean) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = if (blocked) {
            MaterialTheme.colorScheme.error
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        }
    ) {
        Text(
            text = stringResource(
                if (blocked) R.string.log_blocked else R.string.log_allowed
            ),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = if (blocked) {
                MaterialTheme.colorScheme.onError
            } else {
                MaterialTheme.colorScheme.primary
            },
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}
