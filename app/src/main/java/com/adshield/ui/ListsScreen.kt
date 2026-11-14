package com.adshield.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import shivyt.android.adshield.R

/** One updatable list source with its downloaded state. */
data class ListSourceState(
    val name: String,
    val fileName: String,
    val domains: Int?,
    val downloaded: Boolean
)

/**
 * List updates (v1.1.0): download fresh StevenBlack + HaGeZi lists.
 * The user picks whether updates may use mobile data or Wi-Fi only.
 */
@Composable
fun ListsScreen(
    sources: List<ListSourceState>,
    networkSetting: String,
    lastUpdatedText: String?,
    updating: Boolean,
    statusMessage: String?,
    onSetNetwork: (String) -> Unit,
    onUpdateNow: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 22.dp)
    ) {
        Spacer(Modifier.height(18.dp))
        Text(
            text = stringResource(R.string.lists_title),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = stringResource(R.string.lists_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(12.dp))
        for (src in sources) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp, 14.dp, 16.dp, 14.dp)) {
                    Text(
                        text = src.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(
                        text = if (src.downloaded && src.domains != null) {
                            stringResource(R.string.lists_domains, src.domains)
                        } else {
                            stringResource(R.string.lists_bundled)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
        }
        Text(
            text = stringResource(R.string.lists_last_updated, lastUpdatedText ?: "—"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(Modifier.height(14.dp))
        Text(
            text = stringResource(R.string.lists_network),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(Modifier.height(6.dp))
        NetworkOption(
            label = stringResource(R.string.lists_wifi_only),
            selected = networkSetting == "wifi",
            onClick = { onSetNetwork("wifi") }
        )
        NetworkOption(
            label = stringResource(R.string.lists_wifi_or_mobile),
            selected = networkSetting == "any",
            onClick = { onSetNetwork("any") }
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = onUpdateNow,
            enabled = !updating,
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text(
                text = stringResource(
                    if (updating) R.string.lists_updating else R.string.lists_update_now
                ),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        }
        if (statusMessage != null) {
            Spacer(Modifier.height(10.dp))
            Text(
                text = statusMessage,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun NetworkOption(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onClick)
            .padding(vertical = 4.dp)
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}
