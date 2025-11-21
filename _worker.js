import { connect } from "cloudflare:sockets";

// ==========================================
// KONFIGURASI UTAMA (TIDAK DIUBAH)
// ==========================================
const CONFIG = {
  rootDomain: "kaisaronline.web.id",
  serviceName: "premium",
  apiKey: "7qznGifWaacI0PtHzhVle_MUM5u-Aw5Xu2_que70",
  apiEmail: "kopralwann03@gmail.com",
  accountID: "03a4700138e72b9c57362b0423c93d98",
  zoneID: "2addcdf0cab905ea6757695c04e8bd87",
  ports: [443, 80],
  protocols: ["trojan", "vless", "ss"],
  proxyPerPage: 24,
  dnsServer: { address: "8.8.8.8", port: 53 },
  urls: {
    kvProxy: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json",
    proxyBank: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt",
    healthCheck: "https://id1.foolvpn.me/api/v1/check",
    converter: "https://api.foolvpn.me/convert",
    donate: "https://trakteer.id/dickymuliafiqri/tip",
    badWords: "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt"
  },
  cache: { proxyListTTL: 3600000, kvProxyTTL: 1800000 }
};

const APP_DOMAIN = `${CONFIG.serviceName}.${CONFIG.rootDomain}`;
let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];
let cachedKVProxyList = {};
let lastProxyListUpdate = 0;
let lastKVProxyUpdate = 0;

const WS_READY_STATE = { OPEN: 1, CLOSING: 2 };
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// ==========================================
// HELPER & LOGIC CLASSES (TIDAK DIUBAH)
// ==========================================
const helpers = {
  reverse: (s) => s.split("").reverse().join(""),
  getFlagEmoji: (isoCode) => {
    const codePoints = isoCode.toUpperCase().split("").map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  },
  shuffleArray: (array) => {
    let currentIndex = array.length;
    while (currentIndex != 0) {
      let randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;
      [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
  },
  base64ToArrayBuffer: (base64Str) => {
    if (!base64Str) return { error: null };
    try {
      base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
      const decode = atob(base64Str);
      const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
      return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
      return { error };
    }
  },
  arrayBufferToHex: (buffer) => {
    return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
  },
  log: (message, data) => {
    console.log(`[${new Date().toISOString()}] ${message}`, data || "");
  }
};

class CacheManager {
  static isCacheValid(lastUpdate, ttl) {
    const now = Date.now();
    return (now - lastUpdate) < ttl;
  }
  static async getWithCache(fetchFn, cacheVar, lastUpdateVar, ttl) {
    if (cacheVar.length > 0 && CacheManager.isCacheValid(lastUpdateVar, ttl)) {
      return cacheVar;
    }
    try {
      const result = await fetchFn();
      return result;
    } catch (error) {
      helpers.log("Cache fetch error:", error);
      return cacheVar.length > 0 ? cacheVar : [];
    }
  }
}

class ProxyManager {
  static async getKVProxyList() {
    return CacheManager.getWithCache(
      async () => {
        const response = await fetch(CONFIG.urls.kvProxy);
        if (response.status === 200) {
          cachedKVProxyList = await response.json();
          lastKVProxyUpdate = Date.now();
          return cachedKVProxyList;
        }
        return {};
      },
      cachedKVProxyList,
      lastKVProxyUpdate,
      CONFIG.cache.kvProxyTTL
    );
  }
  static async getProxyList(proxyBankUrl = CONFIG.urls.proxyBank) {
    return CacheManager.getWithCache(
      async () => {
        const response = await fetch(proxyBankUrl);
        if (response.status === 200) {
          const text = await response.text() || "";
          const proxyString = text.split("\n").filter(Boolean);
          cachedProxyList = proxyString.map((entry) => {
            const [ip, port, country, org] = entry.split(",");
            return {
              proxyIP: ip || "Unknown",
              proxyPort: port || "Unknown",
              country: country || "Unknown",
              org: org || "Unknown Org",
            };
          }).filter(Boolean);
          lastProxyListUpdate = Date.now();
          return cachedProxyList;
        }
        return [];
      },
      cachedProxyList,
      lastProxyListUpdate,
      CONFIG.cache.proxyListTTL
    );
  }
  static async checkProxyHealth(proxyIP, proxyPort) {
    try {
      const response = await fetch(`${CONFIG.urls.healthCheck}?ip=${proxyIP}:${proxyPort}`);
      return await response.json();
    } catch (error) {
      helpers.log("Proxy health check error:", error);
      return { error: error.message };
    }
  }
}

class WebSocketManager {
  static async handleRequest(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    const url = new URL(request.url);
    const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);
    if (url.pathname.length == 3 || url.pathname.match(",")) {
      const proxyKeys = url.pathname.replace("/", "").toUpperCase().split(",");
      const proxyKey = proxyKeys[Math.floor(Math.random() * proxyKeys.length)];
      const kvProxy = await ProxyManager.getKVProxyList();
      if (kvProxy[proxyKey]) {
        proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];
      }
    } else if (proxyMatch) {
      proxyIP = proxyMatch[1];
    }
    return WebSocketManager.createHandler(webSocket, client, request);
  }
  static createHandler(webSocket, client, request) {
    let addressLog = "";
    let portLog = "";
    const log = (info, event) => {
      helpers.log(`[${addressLog}:${portLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = WebSocketManager.makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };
    let isDNS = false;
    readableWebSocketStream.pipeTo(new WritableStream({
      async write(chunk, controller) {
        if (isDNS) {
          return WebSocketManager.handleUDPOutbound(CONFIG.dnsServer.address, CONFIG.dnsServer.port, chunk, webSocket, null, log);
        }
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }
        const protocol = await ProtocolDetector.detect(chunk);
        let protocolHeader;
        if (protocol === helpers.reverse("trojan")) {
          protocolHeader = ProtocolParser.parseTrojan(chunk);
        } else if (protocol === helpers.reverse("vless")) {
          protocolHeader = ProtocolParser.parseVless(chunk);
        } else if (protocol === helpers.reverse("ss")) {
          protocolHeader = ProtocolParser.parseShadowsocks(chunk);
        } else {
          throw new Error("Protokol Tidak Dikenal!");
        }
        addressLog = protocolHeader.addressRemote;
        portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
        if (protocolHeader.hasError) {
          throw new Error(protocolHeader.message);
        }
        if (protocolHeader.isUDP) {
          if (protocolHeader.portRemote === CONFIG.dnsServer.port) {
            isDNS = true;
          } else {
            throw new Error("UDP hanya didukung untuk port DNS 53");
          }
        }
        if (isDNS) {
          return WebSocketManager.handleUDPOutbound(CONFIG.dnsServer.address, CONFIG.dnsServer.port, chunk, webSocket, protocolHeader.version, log);
        }
        WebSocketManager.handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
      },
      close() { log(`readableWebSocketStream ditutup`); },
      abort(reason) { log(`readableWebSocketStream dibatalkan`, JSON.stringify(reason)); },
    })).catch((err) => { log("readableWebSocketStream pipeTo error", err); });
    return new Response(null, { status: 101, webSocket: client });
  }
  static makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
      start(controller) {
        webSocketServer.addEventListener("message", (event) => {
          if (readableStreamCancel) return;
          const message = event.data;
          controller.enqueue(message);
        });
        webSocketServer.addEventListener("close", () => {
          WebSocketManager.safeCloseWebSocket(webSocketServer);
          if (readableStreamCancel) return;
          controller.close();
        });
        webSocketServer.addEventListener("error", (err) => {
          log("webSocketServer mengalami error");
          controller.error(err);
        });
        const { earlyData, error } = helpers.base64ToArrayBuffer(earlyDataHeader);
        if (error) {
          controller.error(error);
        } else if (earlyData) {
          controller.enqueue(earlyData);
        }
      },
      pull(controller) {},
      cancel(reason) {
        if (readableStreamCancel) return;
        log(`ReadableStream dibatalkan, karena ${reason}`);
        readableStreamCancel = true;
        WebSocketManager.safeCloseWebSocket(webSocketServer);
      },
    });
    return stream;
  }
  static async handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(address, port) {
      const tcpSocket = connect({ hostname: address, port: port });
      remoteSocket.value = tcpSocket;
      log(`terhubung ke ${address}:${port}`);
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      return tcpSocket;
    }
    async function retry() {
      const tcpSocket = await connectAndWrite(proxyIP.split(/[:=-]/)[0] || addressRemote, proxyIP.split(/[:=-]/)[1] || portRemote);
      tcpSocket.closed.catch((error) => { helpers.log("retry tcpSocket closed error", error); }).finally(() => { WebSocketManager.safeCloseWebSocket(webSocket); });
      WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  }
  static async handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
    try {
      let protocolHeader = responseHeader;
      const tcpSocket = connect({ hostname: targetAddress, port: targetPort });
      log(`Terhubung ke ${targetAddress}:${targetPort}`);
      const writer = tcpSocket.writable.getWriter();
      await writer.write(udpChunk);
      writer.releaseLock();
      await tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE.OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() { log(`Koneksi UDP ke ${targetAddress} ditutup`); },
        abort(reason) { helpers.log(`Koneksi UDP ke ${targetPort} dibatalkan karena ${reason}`); },
      }));
    } catch (e) { helpers.log(`Error saat menangani UDP outbound, error ${e.message}`); }
  }
  static async remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
      start() {},
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE.OPEN) { controller.error("webSocket.readyState tidak terbuka, mungkin ditutup"); }
        if (header) {
          webSocket.send(await new Blob([header, chunk]).arrayBuffer());
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() { log(`remoteConnection!.readable ditutup dengan hasIncomingData adalah ${hasIncomingData}`); },
      abort(reason) { helpers.log(`remoteConnection!.readable dibatalkan`, reason); },
    })).catch((error) => {
      helpers.log(`remoteSocketToWS mengalami exception`, error.stack || error);
      WebSocketManager.safeCloseWebSocket(webSocket);
    });
    if (hasIncomingData === false && retry) {
      log(`mencoba kembali`);
      retry();
    }
  }
  static safeCloseWebSocket(socket) {
    try {
      if (socket.readyState === WS_READY_STATE.OPEN || socket.readyState === WS_READY_STATE.CLOSING) { socket.close(); }
    } catch (error) { helpers.log("safeCloseWebSocket error", error); }
  }
}

class ProtocolDetector {
  static async detect(buffer) {
    if (buffer.byteLength >= 62) {
      const trojanDelimiter = new Uint8Array(buffer.slice(56, 60));
      if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
        if (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) {
          if (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04) {
            return helpers.reverse("trojan");
          }
        }
      }
    }
    const vlessDelimiter = new Uint8Array(buffer.slice(1, 17));
    if (helpers.arrayBufferToHex(vlessDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
      return helpers.reverse("vless");
    }
    return helpers.reverse("ss");
  }
}

class ProtocolParser {
  static parseShadowsocks(ssBuffer) {
    const view = new DataView(ssBuffer);
    const addressType = view.getUint8(0);
    let addressLength = 0;
    let addressValueIndex = 1;
    let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 3: addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 4: addressLength = 16; const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `addressType tidak valid untuk ${helpers.reverse("ss")}: ${addressType}` };
    }
    if (!addressValue) { return { hasError: true, message: `Alamat tujuan kosong, tipe alamat adalah: ${addressType}` }; }
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: portIndex + 2, rawClientData: ssBuffer.slice(portIndex + 2), version: null, isUDP: portRemote == CONFIG.dnsServer.port };
  }
  static parseVless(buffer) {
    const version = new Uint8Array(buffer.slice(0, 1));
    let isUDP = false;
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: `perintah ${cmd} tidak didukung` }; }
    const portIndex = 18 + optLength + 1;
    const portBuffer = buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 2: addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 3: addressLength = 16; const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `addressType tidak valid adalah ${addressType}` };
    }
    if (!addressValue) { return { hasError: true, message: `addressValue kosong, addressType adalah ${addressType}` }; }
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.slice(addressValueIndex + addressLength), version: new Uint8Array([version[0], 0]), isUDP: isUDP };
  }
  static parseTrojan(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) { return { hasError: true, message: "data permintaan SOCKS5 tidak valid" }; }
    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) { isUDP = true; } else if (cmd != 1) { throw new Error("Tipe perintah tidak didukung!"); }
    let addressType = view.getUint8(1);
    let addressLength = 0;
    let addressValueIndex = 2;
    let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); } addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `addressType tidak valid adalah ${addressType}` };
    }
    if (!addressValue) { return { hasError: true, message: `alamat kosong, addressType adalah ${addressType}` }; }
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: portIndex + 4, rawClientData: socks5DataBuffer.slice(portIndex + 4), version: null, isUDP: isUDP };
  }
}

class ReverseProxyManager {
  static async handleRequest(request, target, targetPath) {
    const targetUrl = new URL(request.url);
    const [hostname, port] = target.split(":");
    targetUrl.hostname = hostname;
    targetUrl.port = port || "443";
    targetUrl.pathname = targetPath || targetUrl.pathname;
    const modifiedRequest = new Request(targetUrl, request);
    modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));
    try {
      const response = await fetch(modifiedRequest);
      const newResponse = new Response(response.body, response);
      Object.entries(CORS_HEADERS).forEach(([key, value]) => { newResponse.headers.set(key, value); });
      newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");
      return newResponse;
    } catch (error) {
      helpers.log("Reverse proxy error:", error);
      return new Response("Proxy error", { status: 502 });
    }
  }
}

class ConfigManager {
  static generateAllConfig(request, hostName, proxyList, page = 0) {
    const startIndex = CONFIG.proxyPerPage * page;
    try {
      const uuid = crypto.randomUUID();
      const uri = new URL(`${helpers.reverse("trojan")}://${hostName}`);
      uri.searchParams.set("encryption", "none");
      uri.searchParams.set("type", "ws");
      uri.searchParams.set("host", hostName);
      const document = new Document(request);
      document.setTitle("Paket<span class='text-cyan-500'>SSH</span>");
      document.addInfo(`Total Server: ${proxyList.length}`);
      
      for (let i = startIndex; i < startIndex + CONFIG.proxyPerPage; i++) {
        const proxy = proxyList[i];
        if (!proxy) break;
        const { proxyIP, proxyPort, country, org } = proxy;
        uri.searchParams.set("path", `/${proxyIP}-${proxyPort}`);
        const proxies = [];
        for (const port of CONFIG.ports) {
          uri.port = port.toString();
          uri.hash = `${i + 1} ${helpers.getFlagEmoji(country)} ${org} WS ${port == 443 ? "TLS" : "NTLS"} [${CONFIG.serviceName}]`;
          for (const protocol of CONFIG.protocols) {
            if (protocol === "ss") {
              uri.username = btoa(`none:${uuid}`);
              uri.searchParams.set("plugin", `v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxyIP}-${proxyPort};host=${hostName}`);
            } else {
              uri.username = uuid;
              uri.searchParams.delete("plugin");
            }
            uri.protocol = protocol;
            uri.searchParams.set("security", port == 443 ? "tls" : "none");
            uri.searchParams.set("sni", port == 80 && protocol === helpers.reverse("vless") ? "" : hostName);
            proxies.push(uri.toString());
          }
        }
        document.registerProxies({ proxyIP, proxyPort, country, org }, proxies);
      }
      document.addPageButton("Sebelumnya", `/sub/${page > 0 ? page - 1 : 0}`, page > 0 ? false : true);
      document.addPageButton("Berikutnya", `/sub/${page + 1}`, page < Math.floor(proxyList.length / CONFIG.proxyPerPage) ? false : true);
      return document.build();
    } catch (error) {
      helpers.log("Error generating configurations:", error);
      return `Terjadi kesalahan saat membuat konfigurasi. ${error}`;
    }
  }
  static async generateSubscription(request) {
     const url = new URL(request.url);
    const filterCC = url.searchParams.get("cc")?.split(",") || [];
    const filterPort = url.searchParams.get("port")?.split(",") || CONFIG.ports;
    const filterVPN = url.searchParams.get("vpn")?.split(",") || CONFIG.protocols;
    const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
    const filterFormat = url.searchParams.get("format") || "raw";
    const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;
    
    const proxyBankUrl = url.searchParams.get("proxy-list") || "";
    const proxyList = await ProxyManager.getProxyList(proxyBankUrl)
      .then((proxies) => {
        if (filterCC.length) { return proxies.filter((proxy) => filterCC.includes(proxy.country)); }
        return proxies;
      })
      .then((proxies) => { helpers.shuffleArray(proxies); return proxies; });
    
    const uuid = crypto.randomUUID();
    const result = [];
    
    for (const proxy of proxyList) {
      const uri = new URL(`${helpers.reverse("trojan")}://${fillerDomain}`);
      uri.searchParams.set("encryption", "none");
      uri.searchParams.set("type", "ws");
      uri.searchParams.set("host", APP_DOMAIN);
      for (const port of filterPort) {
        for (const protocol of filterVPN) {
          if (result.length >= filterLimit) break;
          uri.protocol = protocol;
          uri.port = port.toString();
          if (protocol == "ss") {
            uri.username = btoa(`none:${uuid}`);
            uri.searchParams.set("plugin", `v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxy.proxyIP}-${proxy.proxyPort};host=${APP_DOMAIN}`);
          } else { uri.username = uuid; }
          uri.searchParams.set("security", port == 443 ? "tls" : "none");
          uri.searchParams.set("sni", port == 80 && protocol == helpers.reverse("vless") ? "" : APP_DOMAIN);
          uri.searchParams.set("path", `/${proxy.proxyIP}-${proxy.proxyPort}`);
          uri.hash = `${result.length + 1} ${helpers.getFlagEmoji(proxy.country)} ${proxy.org} WS ${port == 443 ? "TLS" : "NTLS"} [${CONFIG.serviceName}]`;
          result.push(uri.toString());
        }
      }
    }
    let finalResult = "";
    switch (filterFormat) {
      case "raw": finalResult = result.join("\n"); break;
      case "v2ray": finalResult = btoa(result.join("\n")); break;
      case "clash": case "sfa": case "bfr":
        try {
          const res = await fetch(CONFIG.urls.converter, { method: "POST", body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }) });
          if (res.status == 200) { finalResult = await res.text(); } else { return new Response(res.statusText, { status: res.status, headers: { ...CORS_HEADERS } }); }
        } catch (error) { return new Response("Konversi gagal", { status: 500, headers: { ...CORS_HEADERS } }); }
        break;
    }
    return new Response(finalResult, { status: 200, headers: { ...CORS_HEADERS } });
  }
}

class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${CONFIG.apiKey}`;
    this.accountID = CONFIG.accountID;
    this.zoneID = CONFIG.zoneID;
    this.apiEmail = CONFIG.apiEmail;
    this.apiKey = CONFIG.apiKey;
    this.headers = { Authorization: this.bearer, "X-Auth-Email": this.apiEmail, "X-Auth-Key": this.apiKey };
  }
  async getDomainList() {
    try {
      const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
      const res = await fetch(url, { headers: { ...this.headers } });
      if (res.status == 200) {
        const respJson = await res.json();
        return respJson.result.filter((data) => data.service == CONFIG.serviceName).map((data) => data.hostname);
      }
      return [];
    } catch (error) { helpers.log("Error getting domain list:", error); return []; }
  }
  async registerDomain(domain) {
    try {
      domain = domain.toLowerCase();
      const registeredDomains = await this.getDomainList();
      if (!domain.endsWith(CONFIG.rootDomain)) return 400;
      if (registeredDomains.includes(domain)) return 409;
      try {
        const domainTest = await fetch(`https://${domain.replaceAll("." + APP_DOMAIN, "")}`);
        if (domainTest.status == 530) return domainTest.status;
        const badWordsListRes = await fetch(CONFIG.urls.badWords);
        if (badWordsListRes.status == 200) {
          const badWordsList = (await badWordsListRes.text()).split("\n");
          for (const badWord of badWordsList) { if (domain.includes(badWord.toLowerCase())) { return 403; } }
        } else { return 403; }
      } catch (e) { return 400; }
      const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
      const res = await fetch(url, { method: "PUT", body: JSON.stringify({ environment: "production", hostname: domain, service: CONFIG.serviceName, zone_id: this.zoneID }), headers: { ...this.headers } });
      return res.status;
    } catch (error) { helpers.log("Error registering domain:", error); return 500; }
  }
}

// ==========================================
// DOCUMENT & HTML (MODIFIKASI TAMPILAN)
// ==========================================
class Document {
  constructor(request) {
    this.html = baseHTML;
    this.request = request;
    this.url = new URL(this.request.url);
    this.proxies = [];
  }
  setTitle(title) {
    this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title);
  }
  addInfo(text) {
    // Menyesuaikan dengan statistik di header hero
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `<div class="text-3xl font-bold text-white">${text.split(':')[1]}</div><div class="text-sm text-gray-500">${text.split(':')[0]}</div>`);
  }
  registerProxies(data, proxies) {
    this.proxies.push({ ...data, list: proxies });
  }
  buildProxyGroup() {
    let proxyGroupElement = `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 px-4 max-w-7xl mx-auto">`;
    for (let i = 0; i < this.proxies.length; i++) {
      const proxyData = this.proxies[i];
      const flagUrl = `https://hatscripts.github.io/circle-flags/flags/${proxyData.country.toLowerCase()}.svg`;
      
      // START CARD DESIGN
      proxyGroupElement += `
      <div class="bg-slate-800 rounded-xl border border-slate-700 p-6 hover:border-cyan-500 transition-all duration-300 group lozad">
        <div class="flex justify-between items-start mb-4">
          <div class="flex items-center gap-3">
            <img src="${flagUrl}" width="32" class="rounded-full" />
            <div>
               <h3 class="font-bold text-white group-hover:text-cyan-400 transition-colors text-sm">${proxyData.org}</h3>
               <span class="text-xs font-mono text-gray-400">${proxyData.proxyIP}</span>
            </div>
          </div>
          <div id="ping-${i}" class="px-2 py-1 rounded text-xs font-bold bg-cyan-500/20 text-cyan-400">
            Cek
          </div>
        </div>
        
        <div class="space-y-3 mb-4">
           <div class="flex justify-between text-sm text-gray-400">
             <span>Port</span>
             <span class="text-white font-mono">${proxyData.proxyPort}</span>
           </div>
           <div class="flex justify-between text-sm text-gray-400">
             <span>Country</span>
             <span class="text-white">${proxyData.country}</span>
           </div>
           <input id="config-sample-${i}" class="hidden" type="text" value="${proxyData.list[0]}">
        </div>

        <div class="grid grid-cols-2 gap-2">
      `;

      // BUTTONS
      for (let x = 0; x < proxyData.list.length; x++) {
        const indexName = [
          "Trojan TLS", "VLESS TLS", "SS TLS",
          "Trojan", "VLESS", "SS"
        ];
        const proxy = proxyData.list[x];
        // Style button mirip desain React
        proxyGroupElement += `
          <button onclick="copyToClipboard('${proxy}')" 
            class="py-2 text-xs rounded-lg font-medium transition-colors bg-slate-700 hover:bg-cyan-600 text-white hover:shadow-lg hover:shadow-cyan-500/20">
            ${indexName[x]}
          </button>
        `;
      }
      proxyGroupElement += `</div></div>`; // End card
    }
    proxyGroupElement += `</div>`;
    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", proxyGroupElement);
  }
  
  buildCountryFlag() {
    const proxyBankUrl = this.url.searchParams.get("proxy-list");
    const flagList = [];
    for (const proxy of cachedProxyList) { flagList.push(proxy.country); }
    let flagElement = `<div class="flex gap-2 overflow-x-auto pb-4 px-4 scrollbar-hide justify-center">`;
    flagElement += `<a href="/sub" class="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-gray-300 hover:text-white hover:border-cyan-500 text-sm whitespace-nowrap">All Countries</a>`;
    for (const flag of new Set(flagList)) {
      flagElement += `
        <a href="/sub?cc=${flag}${proxyBankUrl ? "&proxy-list=" + proxyBankUrl : ""}" 
           class="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg hover:border-cyan-500 transition-all min-w-fit">
          <img width="20" src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" />
          <span class="text-sm text-gray-300 font-bold">${flag}</span>
        </a>`;
    }
    flagElement += `</div>`;
    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }

  addPageButton(text, link, isDisabled) {
    const pageButton = `
      <button ${isDisabled ? "disabled" : ""} 
        class="px-6 py-2 bg-slate-800 border border-slate-700 text-cyan-500 font-bold rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-700 hover:border-cyan-500 transition-all" 
        onclick="navigateTo('${link}')">
        ${text}
      </button>
    `;
    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
  }

  build() {
    this.buildProxyGroup();
    this.buildCountryFlag();
    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");
    return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
  }
}

// HTML TEMPLATE (MIRIP REACT DESIGN)
let baseHTML = `
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PaketSSH Clone Proxy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #020617; }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
    </style>
</head>
<body class="bg-slate-950 text-slate-200">
    
    <!-- Navbar -->
    <nav class="bg-slate-900 border-b border-slate-800 sticky top-0 z-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center cursor-pointer">
            <svg class="h-8 w-8 text-cyan-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <span class="ml-2 text-xl font-bold text-white tracking-wider">PAKET<span class="text-cyan-500">SSH</span></span>
          </div>
          <div class="flex items-baseline space-x-4">
             <a href="/" class="bg-cyan-500/10 text-cyan-500 px-3 py-2 rounded-md text-sm font-medium">Home</a>
          </div>
        </div>
      </div>
    </nav>

    <!-- Hero Section -->
    <div class="bg-gradient-to-b from-slate-900 to-slate-800 py-12 px-4 text-center">
      <div class="max-w-4xl mx-auto">
        <div class="inline-flex items-center justify-center p-2 bg-cyan-500/10 rounded-full mb-6">
          <span class="px-3 py-1 text-xs font-bold text-cyan-400 uppercase tracking-wider">Premium Panel v2.0</span>
        </div>
        <h1 class="text-3xl md:text-5xl font-extrabold text-white mb-6 tracking-tight">
          Koneksi Aman Tanpa <span class="text-cyan-500">Batas</span>
        </h1>
        
        <!-- Stats Injection Point -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-6 mt-8 border-t border-slate-700/50 pt-8">
           <div id="total-servers-info">PLACEHOLDER_INFO</div> 
           <!-- Mockup stats to fill visuals -->
           <div><div class="text-3xl font-bold text-white">99.9%</div><div class="text-sm text-gray-500">Uptime</div></div>
           <div><div class="text-3xl font-bold text-white">Free</div><div class="text-sm text-gray-500">Access</div></div>
           <div><div class="text-3xl font-bold text-white">Fast</div><div class="text-sm text-gray-500">Speed</div></div>
        </div>
      </div>
    </div>

    <!-- Country Filter -->
    <div class="bg-slate-950 py-6 border-b border-slate-800/50">
        <div class="max-w-7xl mx-auto">
            PLACEHOLDER_BENDERA_NEGARA
        </div>
    </div>

    <!-- Main Proxy Grid -->
    <main class="py-12 bg-slate-950">
        <div class="flex justify-between items-center max-w-7xl mx-auto px-4 mb-8">
             <h2 class="text-2xl font-bold text-white flex items-center gap-2">
                PLACEHOLDER_JUDUL
             </h2>
        </div>
        
        PLACEHOLDER_PROXY_GROUP

        <!-- Pagination -->
        <div class="flex justify-center gap-4 mt-12">
            PLACEHOLDER_PAGE_BUTTON
        </div>
    </main>

    <!-- Toast Notification -->
    <div id="notification-badge" class="fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-2xl z-50 flex items-center gap-2 bg-cyan-500 text-white opacity-0 transition-opacity duration-300 pointer-events-none">
        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
        <span class="font-medium">Config berhasil disalin!</span>
    </div>

    <!-- Footer -->
    <footer class="bg-slate-900 border-t border-slate-800 py-8 mt-12 text-center text-gray-500 text-sm">
        <p>&copy; 2024 PaketSSH Clone. Powered by Cloudflare Workers.</p>
    </footer>

    <!-- Logic Script (Copy/Paste Functionality) -->
    <script>
      const notification = document.getElementById("notification-badge");

      function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            notification.classList.remove("opacity-0");
            setTimeout(() => {
                notification.classList.add("opacity-0");
            }, 2000);
        });
      }

      function navigateTo(link) {
        window.location.href = link + window.location.search;
      }

      // PING CHECKER
      function checkProxy() {
        // Find all ping elements
        const elements = document.querySelectorAll('[id^="ping-"]');
        elements.forEach((el, index) => {
            const container = el.parentElement.parentElement;
            const ipEl = container.querySelector('.font-mono.text-gray-400');
            
            // Only check if we can find the IP
            if(ipEl) {
                 const target = ipEl.textContent.trim();
                 el.innerText = "Checking...";
                 
                 // Using the worker's check endpoint
                 fetch("/check?target=" + target)
                 .then(res => res.json())
                 .then(data => {
                    if(data.proxyip === true) {
                        el.innerHTML = data.delay + " ms";
                        el.className = "px-2 py-1 rounded text-xs font-bold bg-green-500/20 text-green-400";
                    } else {
                        el.innerText = "Timeout";
                        el.className = "px-2 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400";
                    }
                 })
                 .catch(() => {
                    el.innerText = "Error";
                    el.className = "px-2 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400";
                 });
            }
        });
      }

      // Start helper
      const observer = lozad('.lozad', {
        load: function(el) {
            el.classList.remove('scale-95');
            el.classList.add('scale-100');
        }
      });
      observer.observe();

      // Auto check on load
      window.onload = checkProxy;
    </script>
</body>
</html>
`;

// ==========================================
// MAIN HANDLER (TIDAK DIUBAH)
// ==========================================
export default {
  async fetch(request, env, ctx) {
    try {
      if (CONFIG.apiKey && CONFIG.apiEmail && CONFIG.accountID && CONFIG.zoneID) {
        isApiReady = true;
      }
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") {
        return await WebSocketManager.handleRequest(request);
      }
      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
        let proxyList = (await ProxyManager.getProxyList(proxyBankUrl)).filter((proxy) => {
          if (countrySelect) { return countrySelect.includes(proxy.country); }
          return true;
        });
        const result = ConfigManager.generateAllConfig(request, hostname, proxyList, pageIndex);
        return new Response(result, { status: 200, headers: { "Content-Type": "text/html;charset=utf-8" } });
      }
      if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await ProxyManager.checkProxyHealth(target[0], target[1] || "443");
        return new Response(JSON.stringify(result), { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } });
      }
      if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");
        if (apiPath.startsWith("/domains")) {
          if (!isApiReady) { return new Response("API tidak siap", { status: 500 }); }
          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();
          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), { headers: { ...CORS_HEADERS } });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);
            return new Response(register.toString(), { status: register, headers: { ...CORS_HEADERS } });
          }
        }
        if (apiPath.startsWith("/sub")) { return await ConfigManager.generateSubscription(request); }
        if (apiPath.startsWith("/myip")) {
          return new Response(JSON.stringify({ ip: request.headers.get("cf-connecting-ipv6") || request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"), colo: request.headers.get("cf-ray")?.split("-")[1], ...request.cf }), { headers: { ...CORS_HEADERS } });
        }
      }
      const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
      return await ReverseProxyManager.handleRequest(request, targetReverseProxy);
    } catch (err) {
      helpers.log("Terjadi kesalahan:", err);
      return new Response(`Terjadi kesalahan: ${err.toString()}`, { status: 500, headers: { ...CORS_HEADERS } });
    }
  },
};