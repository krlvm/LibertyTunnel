/*
 * This file is part of LibertyTunnel.
 *
 * LibertyTunnel is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LibertyTunnel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PowerTunnel.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.github.krlvm.powertunnel.plugins.libertytunnel;

import io.github.krlvm.powertunnel.sdk.ServerAdapter;
import io.github.krlvm.powertunnel.sdk.configuration.Configuration;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyStatus;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

public class LibertyTunnel extends PowerTunnelPlugin {

    private static final Logger LOGGER = LoggerFactory.getLogger(LibertyTunnel.class);

    @Override
    public void onProxyInitialization(@NotNull ProxyServer proxy) {
        final Configuration config = readConfiguration();

        String[] blacklist = null;

        final String mirror = config.get("mirror", null);
        if(mirror != null) {
            LOGGER.info("Loading blacklist from mirror...");
            try {
                final URL url = new URL(mirror);
                try(final BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()))) {
                    blacklist = in.lines().toArray(String[]::new);
                }
            } catch (IOException ex) {
                LOGGER.warn("Failed to load blacklist from mirror, using local text file: {}", ex.getMessage(), ex);
            }
        }
        if(blacklist == null) {
            try {
                final String s = readTextFile("government-blacklist.txt");
                blacklist = s.isEmpty() ? new String[0] : s.split("\n");
            } catch (IOException ex) {
                blacklist = new String[0];
                LOGGER.error("Failed to read government blacklist: {}", ex.getMessage(), ex);
            }
        }

        LOGGER.info("Loaded {} blocked websites", blacklist.length);

        final boolean enableSni = config.getBoolean("modify_sni", false);
        if(enableSni) {
            proxy.setMITMEnabled(true);
        }

        final ProxyListener listener = new ProxyListener(
                blacklist,
                config.getBoolean("mix_host_case", false),
                config.getBoolean("mix_host_case_complete", false),
                config.getBoolean("break_before_get", false),
                config.getBoolean("space_after_get", false),
                config.getBoolean("dot_after_host", true),
                config.getBoolean("mix_host_header", true),
                config.getBoolean("send_payload", false) ? 21 : 0,
                config.getBoolean("enable_chunking", true) ? config.getInt("chunk_size", 2) : 0,
                config.getBoolean("full_chunking", false),
                enableSni ? SNITrick.valueOf(config.get("sni_trick", SNITrick.SPOIL.name()).toUpperCase()) : null,
                config.get("fake_sni", "w3.org")
        );
        registerProxyListener(listener, 5);
        registerProxyListener(listener.mitmListener, -5);

        if(config.getBoolean("generate_pac", false) && blacklist.length > 0) {
            final String[] pBlacklist = blacklist;
            registerServerListener(new ServerAdapter() {
                @Override
                public void onProxyStatusChanged(@NotNull ProxyStatus status) {
                    if (status != ProxyStatus.RUNNING) return;
                    LOGGER.info("Saving PAC file...");
                    try {
                        saveTextFile(
                                "libertytunnel.pac",
                                PACGenerator.generatePAC(proxy.getAddress(), getInfo(), pBlacklist)
                        );
                    } catch (IOException ex) {
                        LOGGER.error("Failed to save PAC file: {}", ex.getMessage(), ex);
                    }
                }
            });
        }
    }
}
