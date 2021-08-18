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

import io.github.krlvm.powertunnel.sdk.configuration.Configuration;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Arrays;

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

        final boolean enableSni = config.getBoolean("enable_sni_tricks", false);
        if(enableSni) {
            proxy.setMITMEnabled(true);
        }

        registerProxyListener(new ProxyListener(
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
                enableSni ? SNITrick.valueOf(config.get("sni_trick", SNITrick.SPOIL.name())) : null,
                config.get("fake_sni", "w3.org")
        ), 5);
    }
}
