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

import io.github.krlvm.powertunnel.sdk.http.ProxyRequest;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyAdapter;
import io.github.krlvm.powertunnel.sdk.types.FullAddress;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public final class ProxyListener extends ProxyAdapter {

    private static final String HOST = "Host";

    private final String[] blacklist;
    private final boolean globalMode;

    /** HTTP **/
    private final boolean mixHostCase;
    private final boolean completeMixHostCase;

    private final boolean breakBeforeGet;
    private final boolean spaceAfterGet;

    private final boolean dotAfterHost;
    private final boolean mixHostHeader;

    private final boolean sendPayload;
    private final String[] payload;

    /** HTTPS **/
    private final boolean enableChunking;
    private final int chunkSize;
    private final boolean fullChunking;

    private final boolean enableSniTricks;
    private final SNITrick sniTrick;
    private final String fakeSni;

    protected final MITMListener mitmListener = new MITMListener();

    public ProxyListener(
            final String[] blacklist,
            final boolean mixHostCase,
            final boolean completeMixHostCase,
            final boolean breakBeforeGet,
            final boolean spaceAfterGet,
            final boolean dotAfterHost,
            final boolean mixHostHeader,
            final int payloadLength,
            final int chunkSize,
            final boolean fullChunking,
            final SNITrick sniTrick,
            final String fakeSni
    ) {
        this.blacklist = blacklist;
        this.globalMode = blacklist.length == 0 || (blacklist.length == 1 && "*".equals(blacklist[0]));

        this.mixHostCase = mixHostCase;
        this.completeMixHostCase = completeMixHostCase;

        this.breakBeforeGet = breakBeforeGet;
        this.spaceAfterGet = spaceAfterGet;

        this.dotAfterHost = dotAfterHost;
        this.sendPayload = payloadLength > 0;
        this.mixHostHeader = mixHostHeader;

        this.chunkSize = chunkSize;
        this.fullChunking = fullChunking;
        this.enableChunking = chunkSize > 0;

        this.sniTrick = sniTrick;
        this.fakeSni = fakeSni;
        this.enableSniTricks = sniTrick != null;

        if(payloadLength > 0) {
            final List<String> payload = new ArrayList<>();
            for(int i = 0; i < payloadLength; i++) {
                payload.add(new String(new char[1000]).replace("\0", String.valueOf(i % 10)).intern());
            }
            this.payload = payload.toArray(new String[0]);
        } else {
            this.payload = null;
        }
    }


    @Override
    public void onProxyToServerRequest(@NotNull ProxyRequest request) {
        if(request.isBlocked() || request.isEncrypted()
                || (request.address() != null && request.address().getPort() == 443)) return;

        String host = request.headers().get(HOST);
        if(!isBlocked(request.address() == null ?
                (host == null ? FullAddress.fromString(request.getUri()).getHost() : host) :
                request.address().getHost()
        )) return;

        if(host != null) {
            if(mixHostCase) {
                if(completeMixHostCase) {
                    StringBuilder modified = new StringBuilder();
                    for (int i = 0; i < host.length(); i++) {
                        char c = host.toCharArray()[i];
                        if (i % 2 == 0) {
                            c = Character.toUpperCase(c);
                        }
                        modified.append(c);
                    }
                    host = modified.toString();
                } else {
                    host = host.substring(0, host.length()-1) + host.substring(host.length()-1).toUpperCase();
                }
            }
            if(dotAfterHost) {
                host += '.';
            }
            if(sendPayload) {
                request.headers().remove(HOST);
                for (int i = 0; i < payload.length; i++) {
                    request.headers().set("X-Padding-" + i, payload[i]);
                }
            }
            if(mixHostHeader) {
                request.headers().remove(HOST);
                request.headers().set("hOSt", host);
            } else {
                request.headers().set(HOST, host);
            }
        }
        if(breakBeforeGet || spaceAfterGet) {
            String method = request.getMethod().name();
            if(breakBeforeGet) method = "\r\n" + method;
            if(spaceAfterGet) method += ' ';
            request.setMethod(method);
        }
    }

    @Override
    public Integer onGetChunkSize(@NotNull FullAddress address) {
        if(!enableChunking || !isBlocked(address)) return null;
        return chunkSize;
    }

    @Override
    public Boolean isFullChunking(@NotNull FullAddress address) {
        return fullChunking;
    }

    private class MITMListener extends ProxyAdapter {
        @Override
        public Boolean isMITMAllowed(@NotNull FullAddress address) {
            return isBlocked(address);
        }
    }

    @Override
    public Object onGetSNI(@NotNull String hostname) {
        if(!enableSniTricks || !isBlocked(hostname)) return null;
        switch (sniTrick) {
            case REMOVE: return null;
            case SPOIL: return hostname + ".";
            case FAKE: return fakeSni;
            default: throw new IllegalStateException("Unsupported SNI Trick");
        }
    }



    private boolean isBlocked(final FullAddress address) {
        if(address == null) return globalMode;
        return isBlocked(address.getHost());
    }
    private boolean isBlocked(final String host) {
        if(host == null || globalMode) return globalMode;

        for (String s : blacklist) {
            if(host.endsWith(s)) return true;
        }

        return false;
    }
}
