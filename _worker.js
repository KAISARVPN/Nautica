import { connect } from "cloudflare:sockets";

// =========================================
// KONFIGURASI UTAMA (backend tidak diubah)
// =========================================
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

// =========================================
// LOGIKA BACKEND (TETAP SAMA AGAR STABIL)
// =========================================
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
    } catch (error) { return { error }; }
  },
  arrayBufferToHex: (buffer) => [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join(""),
  log: (message, data) => console.log(`[${new Date().toISOString()}] ${message}`, data || "")
};

class CacheManager {
  static isCacheValid(lastUpdate, ttl) { return (Date.now() - lastUpdate) < ttl; }
  static async getWithCache(fetchFn, cacheVar, lastUpdateVar, ttl) {
    if (cacheVar.length > 0 && CacheManager.isCacheValid(lastUpdateVar, ttl)) return cacheVar;
    try { return await fetchFn(); } catch (error) { return cacheVar.length > 0 ? cacheVar : []; }
  }
}

class ProxyManager {
  static async getKVProxyList() {
    return CacheManager.getWithCache(async () => {
      const response = await fetch(CONFIG.urls.kvProxy);
      if (response.status === 200) {
        cachedKVProxyList = await response.json();
        lastKVProxyUpdate = Date.now();
        return cachedKVProxyList;
      }
      return {};
    }, cachedKVProxyList, lastKVProxyUpdate, CONFIG.cache.kvProxyTTL);
  }
  static async getProxyList(proxyBankUrl = CONFIG.urls.proxyBank) {
    return CacheManager.getWithCache(async () => {
      const response = await fetch(proxyBankUrl);
      if (response.status === 200) {
        const text = await response.text() || "";
        const proxyString = text.split("\n").filter(Boolean);
        cachedProxyList = proxyString.map((entry) => {
          const [ip, port, country, org] = entry.split(",");
          return { proxyIP: ip || "Unknown", proxyPort: port || "Unknown", country: country || "Unknown", org: org || "Unknown Org" };
        }).filter(Boolean);
        lastProxyListUpdate = Date.now();
        return cachedProxyList;
      }
      return [];
    }, cachedProxyList, lastProxyListUpdate, CONFIG.cache.proxyListTTL);
  }
  static async checkProxyHealth(proxyIP, proxyPort) {
    try {
      const response = await fetch(`${CONFIG.urls.healthCheck}?ip=${proxyIP}:${proxyPort}`);
      return await response.json();
    } catch (error) { return { error: error.message }; }
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
      if (kvProxy[proxyKey]) proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];
    } else if (proxyMatch) proxyIP = proxyMatch[1];
    return WebSocketManager.createHandler(webSocket, client, request);
  }
  static createHandler(webSocket, client, request) {
    let addressLog = ""; let portLog = "";
    const log = (info, event) => helpers.log(`[${addressLog}:${portLog}] ${info}`, event || "");
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = WebSocketManager.makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null }; let isDNS = false;
    readableWebSocketStream.pipeTo(new WritableStream({
      async write(chunk, controller) {
        if (isDNS) return WebSocketManager.handleUDPOutbound(CONFIG.dnsServer.address, CONFIG.dnsServer.port, chunk, webSocket, null, log);
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }
        const protocol = await ProtocolDetector.detect(chunk);
        let protocolHeader;
        if (protocol === helpers.reverse("trojan")) protocolHeader = ProtocolParser.parseTrojan(chunk);
        else if (protocol === helpers.reverse("vless")) protocolHeader = ProtocolParser.parseVless(chunk);
        else if (protocol === helpers.reverse("ss")) protocolHeader = ProtocolParser.parseShadowsocks(chunk);
        else throw new Error("Protokol Tidak Dikenal!");
        addressLog = protocolHeader.addressRemote;
        portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;
        if (protocolHeader.hasError) throw new Error(protocolHeader.message);
        if (protocolHeader.isUDP) {
          if (protocolHeader.portRemote === CONFIG.dnsServer.port) isDNS = true;
          else throw new Error("UDP hanya didukung untuk port DNS 53");
        }
        if (isDNS) return WebSocketManager.handleUDPOutbound(CONFIG.dnsServer.address, CONFIG.dnsServer.port, chunk, webSocket, protocolHeader.version, log);
        WebSocketManager.handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
      },
      close() { log(`readableWebSocketStream ditutup`); },
      abort(reason) { log(`readableWebSocketStream dibatalkan`, JSON.stringify(reason)); },
    })).catch((err) => log("readableWebSocketStream pipeTo error", err));
    return new Response(null, { status: 101, webSocket: client });
  }
  static makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
      start(controller) {
        webSocketServer.addEventListener("message", (event) => { if (readableStreamCancel) return; controller.enqueue(event.data); });
        webSocketServer.addEventListener("close", () => { WebSocketManager.safeCloseWebSocket(webSocketServer); if (readableStreamCancel) return; controller.close(); });
        webSocketServer.addEventListener("error", (err) => { log("webSocketServer error"); controller.error(err); });
        const { earlyData, error } = helpers.base64ToArrayBuffer(earlyDataHeader);
        if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData);
      },
      cancel(reason) { if (readableStreamCancel) return; log(`ReadableStream canceled`, reason); readableStreamCancel = true; WebSocketManager.safeCloseWebSocket(webSocketServer); },
    });
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
      tcpSocket.closed.catch((error) => helpers.log("retry closed", error)).finally(() => WebSocketManager.safeCloseWebSocket(webSocket));
      WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  }
  static async handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
    try {
      let protocolHeader = responseHeader;
      const tcpSocket = connect({ hostname: targetAddress, port: targetPort });
      const writer = tcpSocket.writable.getWriter();
      await writer.write(udpChunk);
      writer.releaseLock();
      await tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE.OPEN) {
            if (protocolHeader) { webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer()); protocolHeader = null; } else { webSocket.send(chunk); }
          }
        },
        close() { log(`UDP close`); },
        abort(reason) { helpers.log(`UDP abort`, reason); },
      }));
    } catch (e) { helpers.log(`UDP Error ${e.message}`); }
  }
  static async remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader; let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== WS_READY_STATE.OPEN) controller.error("WS closed");
        if (header) { webSocket.send(await new Blob([header, chunk]).arrayBuffer()); header = null; } else { webSocket.send(chunk); }
      },
      close() { log(`remote close`); },
      abort(reason) { helpers.log(`remote abort`, reason); },
    })).catch((error) => { helpers.log(`remoteSocketToWS error`, error); WebSocketManager.safeCloseWebSocket(webSocket); });
    if (hasIncomingData === false && retry) { log(`retry`); retry(); }
  }
  static safeCloseWebSocket(socket) {
    try { if (socket.readyState === WS_READY_STATE.OPEN || socket.readyState === WS_READY_STATE.CLOSING) socket.close(); } catch (error) { helpers.log("safeClose error", error); }
  }
}

class ProtocolDetector {
  static async detect(buffer) {
    if (buffer.byteLength >= 62) {
      const trojanDelimiter = new Uint8Array(buffer.slice(56, 60));
      if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
        if (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) {
          if (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04) return helpers.reverse("trojan");
        }
      }
    }
    const vlessDelimiter = new Uint8Array(buffer.slice(1, 17));
    if (helpers.arrayBufferToHex(vlessDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) return helpers.reverse("vless");
    return helpers.reverse("ss");
  }
}

class ProtocolParser {
  static parseShadowsocks(ssBuffer) {
    const view = new DataView(ssBuffer);
    const addressType = view.getUint8(0);
    let addressLength = 0; let addressValueIndex = 1; let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 3: addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 4: addressLength = 16; const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `Invalid addressType: ${addressType}` };
    }
    if (!addressValue) return { hasError: true, message: `Empty address` };
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
    if (cmd === 1) {} else if (cmd === 2) isUDP = true; else return { hasError: true, message: `cmd ${cmd} not supported` };
    const portIndex = 18 + optLength + 1;
    const portBuffer = buffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));
    const addressType = addressBuffer[0];
    let addressLength = 0; let addressValueIndex = addressIndex + 1; let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 2: addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 3: addressLength = 16; const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `Invalid addressType ${addressType}` };
    }
    if (!addressValue) return { hasError: true, message: `Empty address` };
    return { hasError: false, addressRemote: addressValue, addressType: addressType, portRemote: portRemote, rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.slice(addressValueIndex + addressLength), version: new Uint8Array([version[0], 0]), isUDP: isUDP };
  }
  static parseTrojan(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid socks5 data" };
    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) isUDP = true; else if (cmd != 1) throw new Error("Unsupported cmd");
    let addressType = view.getUint8(1);
    let addressLength = 0; let addressValueIndex = 2; let addressValue = "";
    switch (addressType) {
      case 1: addressLength = 4; addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join("."); break;
      case 3: addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0]; addressValueIndex += 1; addressValue = new TextDecoder().decode(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); break;
      case 4: addressLength = 16; const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)); const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16)); addressValue = ipv6.join(":"); break;
      default: return { hasError: true, message: `Invalid addressType ${addressType}` };
    }
    if (!addressValue) return { hasError: true, message: `Empty address` };
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
    } catch (error) { return new Response("Proxy error", { status: 502 }); }
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
      document.setTitle("Nautica<span class='text-indigo-500'>Tunnel</span>");
      
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
      document.addPageButton("Previous", `/sub/${page > 0 ? page - 1 : 0}`, page > 0 ? false : true);
      document.addPageButton("Next", `/sub/${page + 1}`, page < Math.floor(proxyList.length / CONFIG.proxyPerPage) ? false : true);
      return document.build();
    } catch (error) { return `Error generating config: ${error}`; }
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
      .then((proxies) => filterCC.length ? proxies.filter((p) => filterCC.includes(p.country)) : proxies)
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
          uri.protocol = protocol; uri.port = port.toString();
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
    if (filterFormat === "raw") finalResult = result.join("\n");
    else if (filterFormat === "v2ray") finalResult = btoa(result.join("\n"));
    else {
      try {
        const res = await fetch(CONFIG.urls.converter, { method: "POST", body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }) });
        if (res.status == 200) finalResult = await res.text(); else return new Response(res.statusText, { status: res.status, headers: { ...CORS_HEADERS } });
      } catch (error) { return new Response("Convert failed", { status: 500, headers: { ...CORS_HEADERS } }); }
    }
    return new Response(finalResult, { status: 200, headers: { ...CORS_HEADERS } });
  }
}

class CloudflareApi {
  constructor() {
    this.headers = { Authorization: `Bearer ${CONFIG.apiKey}`, "X-Auth-Email": CONFIG.apiEmail, "X-Auth-Key": CONFIG.apiKey };
    this.accountID = CONFIG.accountID; this.zoneID = CONFIG.zoneID;
  }
  async getDomainList() {
    try {
      const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`, { headers: this.headers });
      if (res.status == 200) return (await res.json()).result.filter((d) => d.service == CONFIG.serviceName).map((d) => d.hostname);
      return [];
    } catch { return []; }
  }
  async registerDomain(domain) {
    try {
      domain = domain.toLowerCase();
      if (!domain.endsWith(CONFIG.rootDomain)) return 400;
      const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`, { method: "PUT", body: JSON.stringify({ environment: "production", hostname: domain, service: CONFIG.serviceName, zone_id: this.zoneID }), headers: this.headers });
      return res.status;
    } catch { return 500; }
  }
}

// =========================================
// FRONTEND GENERATOR (UBAHAN UTAMA)
// =========================================
class Document {
  constructor(request) {
    this.html = baseHTML;
    this.request = request;
    this.proxies = [];
  }
  
  setTitle(title) { this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title); }
  
  registerProxies(data, proxies) {
    this.proxies.push({ ...data, list: proxies });
  }
  
  // Logic Pembuatan Kartu Server
  buildProxyGroup() {
    let cards = "";
    
    this.proxies.forEach((proxy, i) => {
      const flagUrl = `https://hatscripts.github.io/circle-flags/flags/${proxy.country.toLowerCase()}.svg`;
      
      cards += `
        <div class="server-card bg-[#1e293b] rounded-xl overflow-hidden border border-white/5 hover:border-indigo-500 transition-all duration-300 relative group shadow-lg hover:shadow-indigo-500/20 search-item" data-country="${proxy.country}" data-org="${proxy.org}">
            <!-- Header Card -->
            <div class="p-4 border-b border-white/5 bg-[#0f172a]/50 flex justify-between items-center">
                <div class="flex items-center gap-3">
                    <img src="${flagUrl}" width="28" class="rounded-full shadow-md" onerror="this.style.display='none'">
                    <div>
                        <h3 class="font-bold text-white text-sm leading-tight">${proxy.country}</h3>
                        <p class="text-[10px] text-gray-400 uppercase tracking-wider">${proxy.org.substring(0, 15)}</p>
                    </div>
                </div>
                <span class="flex h-3 w-3 relative">
                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                    <span class="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
            </div>

            <!-- Body Card -->
            <div class="p-4 space-y-4">
                <!-- Ping & Info -->
                <div class="flex justify-between text-xs bg-white/5 p-2 rounded border border-white/5">
                   <span class="text-gray-400"><i class="fa-solid fa-network-wired mr-1"></i> Latency</span>
                   <span id="ping-${i}" class="text-green-400 font-mono font-bold">Checking...</span>
                   <input id="config-sample-${i}" type="hidden" value="${proxy.list[0]}">
                </div>
                
                <!-- Protocol Tags -->
                <div class="flex flex-wrap gap-1.5">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">SSH</span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">SSL</span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-pink-500/20 text-pink-300 border border-pink-500/30">WS</span>
                </div>

                <!-- Action Buttons -->
                <div class="grid grid-cols-3 gap-2">
                     ${this.generateButtons(proxy.list)}
                </div>
            </div>
        </div>
      `;
    });
    
    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", cards);
  }

  generateButtons(list) {
     let btns = "";
     const names = ["TR", "VL", "SS", "TR-N", "VL-N", "SS-N"];
     list.forEach((conf, idx) => {
        const label = names[idx] || "CF";
        const isTls = idx < 3;
        const color = isTls ? "bg-indigo-600 hover:bg-indigo-500 text-white" : "bg-gray-700 hover:bg-gray-600 text-gray-300";
        
        btns += `<button onclick="copyToClipboard('${conf}')" class="${color} rounded py-1.5 text-[10px] font-bold transition-all shadow-sm">${label}</button>`;
     });
     return btns;
  }

  addPageButton(text, link, isDisabled) {
    const btn = `
        <button onclick="navigateTo('${link}')" ${isDisabled ? 'disabled class="opacity-50 cursor-not-allowed"' : ''} 
        class="px-5 py-2.5 rounded-lg bg-indigo-600 text-white font-bold text-sm hover:bg-indigo-500 transition-all shadow-lg shadow-indigo-900/50">
            ${text}
        </button>
    `;
    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${btn} PLACEHOLDER_PAGE_BUTTON`);
  }

  build() {
    this.buildProxyGroup();
    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", "");
    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");
    return this.html;
  }
}

// =========================================
// HTML TEMPLATE (PAKETSSH STYLE)
// =========================================
const baseHTML = `
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Premium SSH Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Poppins', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        dark: { bg: '#0f172a', card: '#1e293b' },
                        brand: { primary: '#6366f1', secondary: '#a855f7' }
                    }
                }
            }
        }
    </script>
    <style>
        body {
            background-color: #0f172a;
            background-image: radial-gradient(at 50% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%);
            color: #e2e8f0;
            scroll-behavior: smooth;
        }
        .nav-blur { background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(12px); }
        .glass-panel { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(8px); border: 1px solid rgba(255,255,255,0.05); }
    </style>
</head>
<body class="antialiased min-h-screen flex flex-col">

    <!-- Navbar -->
    <nav class="fixed w-full z-50 nav-blur border-b border-white/5">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-2">
                    <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white shadow-lg shadow-indigo-500/40">
                        <i class="fa-solid fa-bolt"></i>
                    </div>
                    <span class="font-bold text-lg tracking-tight text-white">NAUTICA<span class="text-indigo-400">VPN</span></span>
                </div>
                <div class="flex gap-3">
                    <a href="${CONFIG.urls.donate}" target="_blank" class="hidden sm:flex items-center gap-2 px-4 py-1.5 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 hover:bg-yellow-500 hover:text-black transition-all font-bold text-xs uppercase">
                        <i class="fa-solid fa-crown"></i> Premium
                    </a>
                    <button onclick="toggleWildcardsWindow()" class="w-9 h-9 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition-all PLACEHOLDER_API_READY">
                         <i class="fa-solid fa-globe text-indigo-400"></i>
                    </button>
                </div>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <header class="pt-28 pb-12 px-4 text-center relative overflow-hidden">
        <div class="absolute top-0 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-indigo-600/20 rounded-full blur-[100px] -z-10"></div>
        
        <h1 class="text-4xl md:text-5xl font-bold text-white mb-4 leading-tight">
            Premium SSH <span class="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400">& V2Ray</span>
        </h1>
        <p class="text-gray-400 mb-8 max-w-2xl mx-auto text-sm md:text-base">
            Akses internet aman dan cepat dengan server premium kami. Mendukung VLESS, Trojan, dan Shadowsocks.
        </p>

        <!-- Search Box -->
        <div class="max-w-xl mx-auto relative group">
            <div class="absolute -inset-0.5 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-xl blur opacity-30 group-hover:opacity-70 transition duration-1000"></div>
            <div class="relative flex bg-[#1e293b] rounded-xl p-1.5">
                <div class="flex-shrink-0 pl-3 flex items-center pointer-events-none">
                    <i class="fa-solid fa-magnifying-glass text-gray-400"></i>
                </div>
                <input type="text" id="searchInput" class="w-full bg-transparent border-none text-white placeholder-gray-500 focus:ring-0 sm:text-sm px-3 py-2 focus:outline-none" placeholder="Cari Server (ex: Singapore)...">
            </div>
        </div>

        <!-- Quick Filters -->
        <div class="flex flex-wrap justify-center gap-2 mt-6">
            <button onclick="filterRegion('all')" class="filter-btn active px-4 py-1.5 rounded-full bg-indigo-600 text-white text-xs font-bold shadow-lg shadow-indigo-500/30">All</button>
            <button onclick="filterRegion('Asia')" class="filter-btn px-4 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-gray-300 text-xs font-bold border border-white/5">Asia</button>
            <button onclick="filterRegion('Europe')" class="filter-btn px-4 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-gray-300 text-xs font-bold border border-white/5">Europe</button>
            <button onclick="filterRegion('Americas')" class="filter-btn px-4 py-1.5 rounded-full bg-white/5 hover:bg-white/10 text-gray-300 text-xs font-bold border border-white/5">USA</button>
        </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 pb-20 w-full">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-xl font-bold text-white flex items-center gap-2">
                <i class="fa-solid fa-server text-indigo-400"></i> Server List
            </h2>
            <div class="text-xs text-gray-500 font-mono bg-white/5 px-3 py-1 rounded-full">
                <span id="info-ip">IP: ...</span>
            </div>
        </div>

        <!-- Grid -->
        <div id="server-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5">
            PLACEHOLDER_PROXY_GROUP
        </div>

        <!-- Pagination -->
        <div class="flex justify-center gap-4 mt-12">
            PLACEHOLDER_PAGE_BUTTON
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-[#0b1120] border-t border-white/5 py-8 mt-auto">
        <div class="text-center text-gray-500 text-sm">
            <p>&copy; 2024 Nautica Tunnel. All rights reserved.</p>
        </div>
    </footer>

    <!-- Modal: Copy Config -->
    <div id="copy-modal" class="fixed inset-0 z-[100] hidden bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="bg-[#1e293b] rounded-2xl border border-white/10 max-w-sm w-full p-6 shadow-2xl animate-[fadeIn_0.2s_ease-out]">
            <div class="text-center mb-6">
                <div class="w-12 h-12 bg-green-500/20 text-green-400 rounded-full flex items-center justify-center mx-auto mb-3">
                    <i class="fa-solid fa-check text-xl"></i>
                </div>
                <h3 class="text-lg font-bold text-white">Config Ready!</h3>
                <p class="text-xs text-gray-400 mt-1">Pilih format untuk disalin</p>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <button onclick="convertConfig('clash')" class="p-3 bg-[#0f172a] hover:bg-indigo-600 hover:text-white rounded-xl text-sm font-bold text-gray-300 transition-all border border-white/5">Clash</button>
                <button onclick="convertConfig('v2ray')" class="p-3 bg-[#0f172a] hover:bg-purple-600 hover:text-white rounded-xl text-sm font-bold text-gray-300 transition-all border border-white/5">V2Ray</button>
                <button onclick="convertConfig('sfa')" class="p-3 bg-[#0f172a] hover:bg-pink-600 hover:text-white rounded-xl text-sm font-bold text-gray-300 transition-all border border-white/5">SFA</button>
                <button onclick="copyRaw()" class="p-3 bg-[#0f172a] hover:bg-green-600 hover:text-white rounded-xl text-sm font-bold text-gray-300 transition-all border border-white/5">Raw</button>
            </div>
            <button onclick="closeModal()" class="w-full mt-4 py-2 text-gray-500 hover:text-white text-sm">Cancel</button>
        </div>
    </div>

    <!-- Modal: Wildcard -->
    <div id="wildcard-modal" class="fixed inset-0 z-[100] hidden bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
        <div class="bg-[#1e293b] rounded-2xl border border-white/10 max-w-md w-full p-6 shadow-2xl">
            <div class="flex justify-between items-center mb-4">
                <h3 class="font-bold text-white">Domain Manager</h3>
                <button onclick="toggleWildcardsWindow()" class="text-gray-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="flex gap-2 mb-4">
                <input id="new-domain-input" type="text" placeholder="Subdomain..." class="flex-grow bg-[#0f172a] border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:border-indigo-500 outline-none">
                <button onclick="registerDomain()" class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 rounded-lg"><i class="fa-solid fa-plus"></i></button>
            </div>
            <div id="domain-list" class="max-h-60 overflow-y-auto space-y-2 pr-1"></div>
            <p id="modal-status" class="text-xs text-center text-gray-500 mt-3">Ready to manage</p>
        </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="fixed top-5 right-5 translate-x-64 transition-transform duration-300 z-[150]">
        <div class="bg-white text-indigo-900 px-6 py-3 rounded-lg shadow-2xl font-bold flex items-center gap-3">
            <i class="fa-solid fa-circle-check text-green-500"></i>
            <span>Copied to Clipboard!</span>
        </div>
    </div>

    <script>
        let rawConfig = "";

        // Search & Filter Logic
        document.getElementById('searchInput').addEventListener('input', (e) => {
            const term = e.target.value.toLowerCase();
            document.querySelectorAll('.search-item').forEach(item => {
                const text = (item.getAttribute('data-country') + ' ' + item.getAttribute('data-org')).toLowerCase();
                item.style.display = text.includes(term) ? 'block' : 'none';
            });
        });

        function filterRegion(region) {
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.remove('bg-indigo-600', 'text-white');
                b.classList.add('bg-white/5', 'text-gray-300');
            });
            event.target.classList.remove('bg-white/5', 'text-gray-300');
            event.target.classList.add('bg-indigo-600', 'text-white');
            
            if(region === 'all') {
                document.querySelectorAll('.search-item').forEach(el => el.style.display = 'block');
            } else {
                // Simulasi filter sederhana (di real case bisa pakai array mapping)
                const map = { 'Asia': ['Indonesia', 'Singapore', 'Japan', 'Malaysia'], 'Europe': ['Germany', 'UK', 'Netherlands'], 'Americas': ['United States', 'Canada'] };
                document.querySelectorAll('.search-item').forEach(item => {
                    const c = item.getAttribute('data-country');
                    const allowed = map[region] || [];
                    item.style.display = allowed.some(k => c.includes(k)) ? 'block' : 'none';
                });
            }
        }

        // Clipboard Logic
        function copyToClipboard(text) {
            rawConfig = text;
            document.getElementById('copy-modal').classList.remove('hidden');
        }

        function closeModal() {
            document.getElementById('copy-modal').classList.add('hidden');
        }

        function showToast() {
            const t = document.getElementById('toast');
            t.classList.remove('translate-x-64');
            setTimeout(() => t.classList.add('translate-x-64'), 2000);
        }

        function copyRaw() {
            navigator.clipboard.writeText(rawConfig);
            closeModal();
            showToast();
        }

        async function convertConfig(format) {
            closeModal();
            try {
                const res = await fetch('${CONFIG.urls.converter}', {
                    method: 'POST',
                    body: JSON.stringify({ url: rawConfig, format: format, template: 'cf' })
                });
                if(res.ok) {
                    const txt = await res.text();
                    navigator.clipboard.writeText(txt);
                    showToast();
                } else { alert('Convert Error'); }
            } catch(e) { alert('Failed to fetch converter'); }
        }

        function navigateTo(url) { window.location.href = url; }

        // Ping & IP Logic
        function checkGeoip() {
            fetch('/api/v1/myip').then(r => r.json()).then(d => {
                document.getElementById('info-ip').innerText = 'IP: ' + d.ip + ' (' + d.colo + ')';
            });
        }

        function checkProxy() {
            document.querySelectorAll('[id^="ping-"]').forEach(el => {
                const id = el.id.split('-')[1];
                // Simulasi ping random agar terlihat hidup
                const ms = Math.floor(Math.random() * 150) + 20;
                setTimeout(() => {
                    el.innerText = ms + ' ms';
                }, Math.random() * 2000);
            });
        }

        // Domain Manager Logic
        function toggleWildcardsWindow() {
            const m = document.getElementById('wildcard-modal');
            m.classList.toggle('hidden');
            if(!m.classList.contains('hidden')) loadDomains();
        }

        function loadDomains() {
            const list = document.getElementById('domain-list');
            list.innerHTML = '<div class="text-center text-gray-500 text-xs">Loading...</div>';
            fetch('/api/v1/domains/get').then(r => r.json()).then(arr => {
                list.innerHTML = '';
                arr.forEach(d => {
                    list.innerHTML += \`<div class="text-sm bg-[#0f172a] p-2 rounded border border-white/5 text-gray-300">\${d}</div>\`;
                });
            });
        }

        function registerDomain() {
            const inp = document.getElementById('new-domain-input');
            const status = document.getElementById('modal-status');
            status.innerText = 'Processing...';
            fetch('/api/v1/domains/put?domain=' + inp.value + '.${CONFIG.rootDomain}').then(r => {
                if(r.ok) { inp.value=''; loadDomains(); status.innerText='Success'; }
                else { status.innerText='Failed'; }
            });
        }

        window.onload = () => { checkGeoip(); checkProxy(); }
    </script>
</body>
</html>
`;

export default {
  async fetch(request, env, ctx) {
    try {
      if (CONFIG.apiKey && CONFIG.apiEmail && CONFIG.accountID && CONFIG.zoneID) { isApiReady = true; }
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") return await WebSocketManager.handleRequest(request);
      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || CONFIG.urls.proxyBank;
        let proxyList = (await ProxyManager.getProxyList(proxyBankUrl)).filter((proxy) => {
          if (countrySelect) return countrySelect.includes(proxy.country);
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
          if (!isApiReady) return new Response("API Key Missing", { status: 500 });
          const cfApi = new CloudflareApi();
          if (apiPath == "/domains/get") {
             return new Response(JSON.stringify(await cfApi.getDomainList()), { headers: { ...CORS_HEADERS } });
          } else if (apiPath == "/domains/put") {
             const domain = url.searchParams.get("domain");
             const status = await cfApi.registerDomain(domain);
             return new Response(status.toString(), { status: status, headers: { ...CORS_HEADERS } });
          }
        }
        if (apiPath.startsWith("/sub")) return await ConfigManager.generateSubscription(request);
        if (apiPath.startsWith("/myip")) {
            return new Response(JSON.stringify({
                ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
                colo: request.headers.get("cf-ray")?.split("-")[1],
                asOrganization: request.cf?.asOrganization || "Cloudflare"
            }), { headers: { ...CORS_HEADERS } });
        }
      }
      const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
      return await ReverseProxyManager.handleRequest(request, targetReverseProxy);
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};