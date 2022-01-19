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
 * along with LibertyTunnel.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.github.krlvm.powertunnel.plugins.libertytunnel;

import io.github.krlvm.powertunnel.sdk.ServerAdapter;
import io.github.krlvm.powertunnel.sdk.configuration.Configuration;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyStatus;
import io.github.krlvm.powertunnel.sdk.utiities.TextReader;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class LibertyTunnel extends PowerTunnelPlugin {

    private static final Logger LOGGER = LoggerFactory.getLogger(LibertyTunnel.class);

    @Override
    public void onProxyInitialization(@NotNull ProxyServer proxy) {
        final Configuration config = readConfiguration();

        final Set<String> blacklistSet = new HashSet<>();

        final String mirror = config.get("mirror", null);
        final long interval = getMirrorInterval(config.get("mirror_interval", "interval_2"));
        if (mirror != null && !mirror.trim().isEmpty()) {
            if ((System.currentTimeMillis() - config.getLong("last_mirror_load", 0)) < interval) {
                if(!loadBlacklistFromCache(blacklistSet)) {
                    loadBlacklistFromMirror(blacklistSet, mirror, config, interval != 0);
                }
            } else {
                if(!loadBlacklistFromMirror(blacklistSet, mirror, config, interval != 0)) {
                    loadBlacklistFromCache(blacklistSet);
                }
            }
        }

        final String[] blacklist;
        if (proxy.areHostnamesAvailable()) {
            LOGGER.info("Loading local blacklist...");
            try {
                blacklistSet.addAll(Arrays.asList(readTextFile("government-blacklist.txt").split("\n")));
            } catch (IOException ex) {
                LOGGER.error("Failed to read local blacklist: {}", ex.getMessage(), ex);
            }

            blacklist = blacklistSet.toArray(new String[0]);

            LOGGER.info("Loaded {} blocked websites", blacklist.length);
        } else {
            LOGGER.warn("Blacklist is not supported when using VPN-level hostname resolving");
            blacklist = new String[0];
        }

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
            registerServerListener(new ServerAdapter() {
                @Override
                public void onProxyStatusChanged(@NotNull ProxyStatus status) {
                    if (status != ProxyStatus.RUNNING) return;
                    LOGGER.info("Saving PAC file...");
                    try {
                        saveTextFile(
                                "libertytunnel.pac",
                                PACGenerator.generatePAC(proxy.getAddress(), getInfo(), blacklist)
                        );
                    } catch (IOException ex) {
                        LOGGER.error("Failed to save PAC file: {}", ex.getMessage(), ex);
                    }
                }
            });
        }
    }

    private boolean loadBlacklistFromMirror(Set<String> blacklist, String mirror, Configuration config, boolean caching) {
        LOGGER.info("Loading blacklist from mirror...");
        try {
            final String raw = TextReader.read(new URL(mirror).openStream());
            blacklist.addAll(Arrays.asList(raw.split("\n")));
            if (caching) {
                try {
                    config.setLong("last_mirror_load", System.currentTimeMillis());
                    saveConfiguration();
                } catch (IOException ex) {
                    LOGGER.warn("Failed to save the time of the last load of the blacklist from the mirror: {}", ex.getMessage(), ex);
                }
                try {
                    saveTextFile("government-blacklist-cache.txt", raw);
                } catch (IOException ex) {
                    LOGGER.warn("Failed to save cached blacklist: {}", ex.getMessage(), ex);
                }
            }
            return true;
        } catch (IOException ex) {
            LOGGER.warn("Failed to load blacklist from mirror: {}", ex.getMessage(), ex);
            return false;
        }
    }

    private boolean loadBlacklistFromCache(Set<String> blacklist) {
        LOGGER.info("Loading blacklist from cache...");
        try {
            blacklist.addAll(Arrays.asList(readTextFile("government-blacklist-cache.txt").split("\n")));
            return true;
        } catch (IOException ex) {
            LOGGER.error("Failed to read cached blacklist: {}", ex.getMessage(), ex);
            return false;
        }
    }

    private static long getMirrorInterval(String key) {
        switch (key) {
            case "interval_5": return 3 * 24 * 60 * 60 * 1000;
            case "interval_4": return 2 * 24 * 60 * 60 * 1000;
            case "interval_3": return 24 * 60 * 60 * 1000;
            case "interval_1": return 0;
            default: case "interval_2": return 12 * 60 * 60 * 1000;
        }
    }
}
