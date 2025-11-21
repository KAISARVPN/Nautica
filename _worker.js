import { connect } from "cloudflare:sockets";

// =========================================
// KONFIGURASI UTAMA
// =========================================
const CONFIG = {
  // Informasi Akun Cloudflare
  rootDomain: "kaisaronline.web.id",
  serviceName: "premium",
  apiKey: "7qznGifWaacI0PtHzhVle_MUM5u-Aw5Xu2_que70",
  apiEmail: "kopralwann03@gmail.com",
  accountID: "03a4700138e72b9c57362b0423c93d98",
  zoneID: "2addcdf0cab905ea6757695c04e8bd87",
  
  // Konfigurasi Server
  ports: [443, 80],
  protocols: ["trojan", "vless", "ss"],
  proxyPerPage: 24, // Jumlah proxy per halaman
  
  // Konfigurasi DNS
  dnsServer: {
    address: "8.8.8.8",
    port: 53
  },
  
  // URL Eksternal (Resource)
  urls: {
    kvProxy: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json",
    proxyBank: "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt",
    healthCheck: "https://id1.foolvpn.me/api/v1/check",
    converter: "https://api.foolvpn.me/convert",
    donate: "https://trakteer.id/dickymuliafiqri/tip",
    badWords: "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt"
  },
  
  // Pengaturan Cache
  cache: {
    proxyListTTL: 3600000, // 1 jam
    kvProxyTTL: 1800000,   // 30 menit
  }
};

// Konstanta Aplikasi
const APP_DOMAIN = `${CONFIG.serviceName}.${CONFIG.rootDomain}`;

// Variabel Global
let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];
let cachedKVProxyList = {};
let lastProxyListUpdate = 0;
let lastKVProxyUpdate = 0;

// Konstanta State WebSocket
const WS_READY_STATE = {
  OPEN: 1,
  CLOSING: 2
};

// Opsi Header CORS
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// =========================================
// LOGIKA BACKEND (Proxy & WebSocket)
// =========================================

// Fungsi Helper
const helpers = {
  reverse: (s) => s.split("").reverse().join(""),
  getFlagEmoji: (isoCode) => {
    const codePoints = isoCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0));
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

// Kelas Cache
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

// Kelas Proxy Manager
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
          
          cachedProxyList = proxyString
            .map((entry) => {
              const [ip, port, country, org] = entry.split(",");
              return {
                proxyIP: ip || "Unknown",
                proxyPort: port || "Unknown",
                country: country || "Unknown",
                org: org || "Unknown Org",
              };
            })
            .filter(Boolean);
          
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

// Kelas WebSocket Manager
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
    
    readableWebSocketStream
      .pipeTo(
        new WritableStream({
          async write(chunk, controller) {
            if (isDNS) {
              return WebSocketManager.handleUDPOutbound(
                CONFIG.dnsServer.address, 
                CONFIG.dnsServer.port, 
                chunk, 
                webSocket, 
                null, 
                log
              );
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
              return WebSocketManager.handleUDPOutbound(
                CONFIG.dnsServer.address,
                CONFIG.dnsServer.port,
                chunk,
                webSocket,
                protocolHeader.version,
                log
              );
            }
            
            WebSocketManager.handleTCPOutBound(
              remoteSocketWrapper,
              protocolHeader.addressRemote,
              protocolHeader.portRemote,
              protocolHeader.rawClientData,
              webSocket,
              protocolHeader.version,
              log
            );
          },
          close() {
            log(`readableWebSocketStream ditutup`);
          },
          abort(reason) {
            log(`readableWebSocketStream dibatalkan`, JSON.stringify(reason));
          },
        })
      )
      .catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
      });
    
    return new Response(null, {
      status: 101,
      webSocket: client,
    });
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
  
  static async handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    responseHeader,
    log
  ) {
    async function connectAndWrite(address, port) {
      const tcpSocket = connect({
        hostname: address,
        port: port,
      });
      remoteSocket.value = tcpSocket;
      log(`terhubung ke ${address}:${port}`);
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      return tcpSocket;
    }
    
    async function retry() {
      const tcpSocket = await connectAndWrite(
        proxyIP.split(/[:=-]/)[0] || addressRemote,
        proxyIP.split(/[:=-]/)[1] || portRemote
      );
      tcpSocket.closed
        .catch((error) => {
          helpers.log("retry tcpSocket closed error", error);
        })
        .finally(() => {
          WebSocketManager.safeCloseWebSocket(webSocket);
        });
      WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }
    
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    WebSocketManager.remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  }
  
  static async handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
    try {
      let protocolHeader = responseHeader;
      const tcpSocket = connect({
        hostname: targetAddress,
        port: targetPort,
      });
      
      log(`Terhubung ke ${targetAddress}:${targetPort}`);
      
      const writer = tcpSocket.writable.getWriter();
      await writer.write(udpChunk);
      writer.releaseLock();
      
      await tcpSocket.readable.pipeTo(
        new WritableStream({
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
          close() {
            log(`Koneksi UDP ke ${targetAddress} ditutup`);
          },
          abort(reason) {
            helpers.log(`Koneksi UDP ke ${targetPort} dibatalkan karena ${reason}`);
          },
        })
      );
    } catch (e) {
      helpers.log(`Error saat menangani UDP outbound, error ${e.message}`);
    }
  }
  
  static async remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasIncomingData = false;
    
    await remoteSocket.readable
      .pipeTo(
        new WritableStream({
          start() {},
          async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE.OPEN) {
              controller.error("webSocket.readyState tidak terbuka, mungkin ditutup");
            }
            if (header) {
              webSocket.send(await new Blob([header, chunk]).arrayBuffer());
              header = null;
            } else {
              webSocket.send(chunk);
            }
          },
          close() {
            log(`remoteConnection!.readable ditutup dengan hasIncomingData adalah ${hasIncomingData}`);
          },
          abort(reason) {
            helpers.log(`remoteConnection!.readable dibatalkan`, reason);
          },
        })
      )
      .catch((error) => {
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
      if (socket.readyState === WS_READY_STATE.OPEN || socket.readyState === WS_READY_STATE.CLOSING) {
        socket.close();
      }
    } catch (error) {
      helpers.log("safeCloseWebSocket error", error);
    }
  }
}

// Kelas Protocol Detector & Parser
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
      case 1:
        addressLength = 4;
        addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 3:
        addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 4:
        addressLength = 16;
        const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(dataView.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: `addressType tidak valid untuk ${helpers.reverse("ss")}: ${addressType}` };
    }
    
    if (!addressValue) {
      return { hasError: true, message: `Alamat tujuan kosong` };
    }
    
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: portIndex + 2,
      rawClientData: ssBuffer.slice(portIndex + 2),
      version: null,
      isUDP: portRemote == CONFIG.dnsServer.port,
    };
  }
  
  static parseVless(buffer) {
    const version = new Uint8Array(buffer.slice(0, 1));
    let isUDP = false;
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
    
    if (cmd === 2) isUDP = true;
    
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
      case 1:
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 2:
        addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 3:
        addressLength = 16;
        const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(dataView.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: `addressType tidak valid` };
    }
    
    if (!addressValue) return { hasError: true, message: `addressValue kosong` };
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: addressValueIndex + addressLength,
      rawClientData: buffer.slice(addressValueIndex + addressLength),
      version: new Uint8Array([version[0], 0]),
      isUDP: isUDP,
    };
  }
  
  static parseTrojan(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "data permintaan SOCKS5 tidak valid" };
    
    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) isUDP = true;
    else if (cmd != 1) throw new Error("Tipe perintah tidak didukung!");
    
    let addressType = view.getUint8(1);
    let addressLength = 0;
    let addressValueIndex = 2;
    let addressValue = "";
    
    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 3:
        addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 4:
        addressLength = 16;
        const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(dataView.getUint16(i * 2).toString(16));
        }
        addressValue = ipv6.join(":");
        break;
      default:
        return { hasError: true, message: `addressType tidak valid` };
    }
    
    if (!addressValue) return { hasError: true, message: `alamat kosong` };
    
    const portIndex = addressValueIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    
    return {
      hasError: false,
      addressRemote: addressValue,
      addressType: addressType,
      portRemote: portRemote,
      rawDataIndex: portIndex + 4,
      rawClientData: socks5DataBuffer.slice(portIndex + 4),
      version: null,
      isUDP: isUDP,
    };
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
      Object.entries(CORS_HEADERS).forEach(([key, value]) => {
        newResponse.headers.set(key, value);
      });
      newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");
      return newResponse;
    } catch (error) {
      helpers.log("Reverse proxy error:", error);
      return new Response("Proxy error", { status: 502 });
    }
  }
}

// =========================================
// CONFIG GENERATOR & CLOUDFLARE API
// =========================================
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
      document.setTitle(`Selamat Datang di <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600 font-extrabold">NAUTICA</span>`);
      document.addInfo(`Total: ${proxyList.length}`);
      document.addInfo(`Halaman: ${page}/${Math.floor(proxyList.length / CONFIG.proxyPerPage)}`);
      
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
              uri.searchParams.set(
                "plugin",
                `v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxyIP}-${proxyPort};host=${hostName}`
              );
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
        if (filterCC.length) return proxies.filter((proxy) => filterCC.includes(proxy.country));
        return proxies;
      })
      .then((proxies) => {
        helpers.shuffleArray(proxies);
        return proxies;
      });
    
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
            uri.searchParams.set(
              "plugin",
              `v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxy.proxyIP}-${proxy.proxyPort};host=${APP_DOMAIN}`
            );
          } else {
            uri.username = uuid;
          }
          
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
      case "clash":
      case "sfa":
      case "bfr":
        try {
          const res = await fetch(CONFIG.urls.converter, {
            method: "POST",
            body: JSON.stringify({ url: result.join(","), format: filterFormat, template: "cf" }),
          });
          if (res.status == 200) finalResult = await res.text();
          else return new Response(res.statusText, { status: res.status, headers: { ...CORS_HEADERS } });
        } catch (error) {
          return new Response("Konversi gagal", { status: 500, headers: { ...CORS_HEADERS } });
        }
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
    } catch (error) { return []; }
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
          for (const badWord of badWordsList) {
            if (domain.includes(badWord.toLowerCase())) return 403;
          }
        } else { return 403; }
      } catch (e) { return 400; }
      
      const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
      const res = await fetch(url, {
        method: "PUT",
        body: JSON.stringify({ environment: "production", hostname: domain, service: CONFIG.serviceName, zone_id: this.zoneID }),
        headers: { ...this.headers },
      });
      return res.status;
    } catch (error) { return 500; }
  }
}

// =========================================
// FRONTEND (HTML & UI) - REDESIGNED
// =========================================
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
    text = `<div class="flex items-center gap-2 px-3 py-1 bg-slate-800/50 border border-slate-700 rounded-full text-xs font-medium text-cyan-300 shadow-sm backdrop-blur-sm">${text}</div>`;
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `${text}\nPLACEHOLDER_INFO`);
  }
  
  registerProxies(data, proxies) {
    this.proxies.push({ ...data, list: proxies });
  }
  
  buildProxyGroup() {
    let proxyGroupElement = `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 p-4">`;
    
    for (let i = 0; i < this.proxies.length; i++) {
      const proxyData = this.proxies[i];
      
      // NEW CARD DESIGN
      proxyGroupElement += `
      <div class="group relative overflow-hidden rounded-2xl bg-slate-800/60 backdrop-blur-xl border border-slate-700 transition-all duration-300 hover:border-cyan-500 hover:shadow-lg hover:shadow-cyan-500/20 hover:-translate-y-1">
        
        <!-- Header Card -->
        <div class="relative p-5 pb-3">
          <div class="flex justify-between items-start">
             <div class="flex items-center gap-3">
                <div class="relative w-10 h-10 rounded-full overflow-hidden border-2 border-slate-600 shadow-md group-hover:border-cyan-400 transition-colors">
                   <img class="w-full h-full object-cover" src="https://hatscripts.github.io/circle-flags/flags/${proxyData.country.toLowerCase()}.svg" alt="${proxyData.country}" />
                </div>
                <div>
                  <h5 class="font-bold text-white text-sm tracking-wide truncate w-32 group-hover:text-cyan-300 transition-colors">${proxyData.org}</h5>
                  <p class="text-xs text-slate-400 font-mono mt-0.5 flex items-center gap-1">
                     <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                     ${proxyData.proxyIP}:${proxyData.proxyPort}
                  </p>
                </div>
             </div>
          </div>
        </div>

        <!-- Status Bar -->
        <div class="px-5 py-2 bg-slate-900/30 border-y border-slate-700/50 flex justify-between items-center">
           <div id="ping-${i}" class="text-[10px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <svg class="animate-spin h-3 w-3 text-cyan-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              SCANNING...
           </div>
           <div id="container-region-check-${i}">
             <input id="config-sample-${i}" class="hidden" type="text" value="${proxyData.list[0]}">
           </div>
        </div>

        <!-- Action Buttons -->
        <div class="p-4 grid grid-cols-2 gap-2">
      `;
      
      for (let x = 0; x < proxyData.list.length; x++) {
        const protocolNames = ["TR TLS", "VL TLS", "SS TLS", "TR NTLS", "VL NTLS", "SS NTLS"];
        const btnColor = x < 3 ? "bg-cyan-600 hover:bg-cyan-500" : "bg-slate-700 hover:bg-slate-600";
        const proxy = proxyData.list[x];
        
        proxyGroupElement += `
          <button 
            class="${btnColor} text-white text-[10px] font-bold py-2 px-3 rounded-lg transition-all active:scale-95 shadow-md flex items-center justify-center gap-1"
            onclick="copyToClipboard('${proxy}')"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="w-3 h-3">
              <path d="M7 3.5A1.5 1.5 0 0 1 8.5 2h3.879a1.5 1.5 0 0 1 1.06.44l3.122 3.12A1.5 1.5 0 0 1 17 6.622V12.5a1.5 1.5 0 0 1-1.5 1.5h-1v-3.379a3 3 0 0 0-.879-2.121L10.5 5.379A3 3 0 0 0 8.379 4.5H7v-1Z" />
              <path d="M4.5 6A1.5 1.5 0 0 0 3 7.5v9A1.5 1.5 0 0 0 4.5 18h7a1.5 1.5 0 0 0 1.5-1.5v-5.879a1.5 1.5 0 0 0-.44-1.06L9.44 6.439A1.5 1.5 0 0 0 8.379 6H4.5Z" />
            </svg>
            ${protocolNames[x]}
          </button>
        `;
      }
      
      proxyGroupElement += `</div></div>`;
    }
    
    proxyGroupElement += `</div>`;
    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", proxyGroupElement);
  }
  
  buildCountryFlag() {
    const proxyBankUrl = this.url.searchParams.get("proxy-list");
    const flagList = cachedProxyList.map(p => p.country);
    
    let flagElement = "";
    for (const flag of new Set(flagList)) {
      flagElement += `
        <a href="/sub?cc=${flag}${proxyBankUrl ? "&proxy-list=" + proxyBankUrl : ""}" 
           class="group relative p-2 rounded-xl hover:bg-slate-700/50 transition-all duration-200 flex items-center justify-center"
           title="${flag}">
          <img class="w-8 h-8 transform group-hover:scale-110 transition-transform drop-shadow-md" 
               src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" />
        </a>`;
    }
    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }
  
  addPageButton(text, link, isDisabled) {
    const buttonClass = isDisabled 
      ? "opacity-50 cursor-not-allowed bg-slate-800 text-slate-500 border-slate-700" 
      : "bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-600 shadow-lg shadow-cyan-500/30 hover:-translate-y-0.5";
      
    const pageButton = `
      <li>
        <button ${isDisabled ? "disabled" : ""} 
                class="px-5 py-2 rounded-xl text-sm font-bold transition-all duration-300 border ${buttonClass}" 
                onclick="navigateTo('${link}')">
          ${text}
        </button>
      </li>`;
    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
  }
  
  build() {
    this.buildProxyGroup();
    this.buildCountryFlag();
    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "flex" : "hidden");
    return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
  }
}

// =========================================
// HTML TEMPLATE - MODERN & CYBERPUNK THEME
// =========================================
let baseHTML = `
<!DOCTYPE html>
<html lang="id" id="html" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Nautica Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
      body { font-family: 'Inter', sans-serif; background-color: #0f172a; }
      
      /* Custom Scrollbar */
      ::-webkit-scrollbar { width: 8px; height: 8px; }
      ::-webkit-scrollbar-track { background: #1e293b; }
      ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
      ::-webkit-scrollbar-thumb:hover { background: #64748b; }
      
      .glass-panel {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.05);
      }
      
      .animate-float { animation: float 6s ease-in-out infinite; }
      @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>tailwind.config = { darkMode: 'class' }</script>
  </head>
  <body class="text-slate-200 antialiased selection:bg-cyan-500 selection:text-white overflow-x-hidden">
    
    <!-- Background Mesh Gradient -->
    <div class="fixed inset-0 z-[-1] overflow-hidden pointer-events-none">
      <div class="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-cyan-900/20 blur-[120px] animate-pulse"></div>
      <div class="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-blue-900/20 blur-[120px] animate-pulse"></div>
    </div>

    <!-- Toast Notification -->
    <div id="notification-badge" class="fixed top-6 right-6 z-50 transform transition-all duration-500 translate-x-[150%] opacity-0">
      <div class="glass-panel px-6 py-4 rounded-2xl shadow-2xl border-l-4 border-emerald-500 flex items-center gap-4">
        <div class="bg-emerald-500/20 p-2 rounded-full text-emerald-400">
           <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
        </div>
        <div>
          <h4 class="font-bold text-white">Berhasil!</h4>
          <p class="text-sm text-slate-400">Konfigurasi telah disalin.</p>
        </div>
      </div>
    </div>

    <!-- Sidebar Country Filter (Floating) -->
    <aside class="fixed left-4 top-1/2 -translate-y-1/2 z-40 hidden lg:flex flex-col gap-3">
      <div class="glass-panel p-3 rounded-2xl flex flex-col gap-2 shadow-2xl max-h-[70vh] overflow-y-auto scrollbar-hide">
        PLACEHOLDER_BENDERA_NEGARA
      </div>
    </aside>

    <!-- Main Layout -->
    <main class="min-h-screen flex flex-col pb-20">
      
      <!-- Header Section -->
      <header class="sticky top-0 z-30 glass-panel border-b border-slate-700/50 shadow-lg">
        <div class="container mx-auto px-4 py-4">
          <div class="flex flex-col md:flex-row justify-between items-center gap-4">
            
            <!-- Title Area -->
            <div class="text-center md:text-left">
              <h1 class="text-2xl md:text-3xl tracking-tight font-black text-white">
                PLACEHOLDER_JUDUL
              </h1>
              <div class="flex flex-wrap justify-center md:justify-start gap-2 mt-2">
                PLACEHOLDER_INFO
              </div>
            </div>

            <!-- User Info Card -->
            <div class="bg-slate-900/50 border border-slate-700 rounded-xl p-3 px-5 flex gap-6 text-xs font-mono text-slate-400">
               <div>
                 <span class="block text-slate-500 uppercase text-[10px] tracking-wider">Your IP</span>
                 <span id="container-info-ip" class="text-cyan-400 font-bold">Loading...</span>
               </div>
               <div class="hidden sm:block">
                 <span class="block text-slate-500 uppercase text-[10px] tracking-wider">Country</span>
                 <span id="container-info-country" class="text-white">...</span>
               </div>
               <div class="hidden sm:block">
                 <span class="block text-slate-500 uppercase text-[10px] tracking-wider">ISP</span>
                 <span id="container-info-isp" class="text-white">...</span>
               </div>
            </div>

          </div>
        </div>
      </header>

      <!-- Content Area -->
      <div class="container mx-auto mt-8 flex-1">
         <!-- Mobile Country Scroll -->
         <div class="lg:hidden flex overflow-x-auto gap-3 pb-4 px-4 mb-4 scrollbar-hide">
            PLACEHOLDER_BENDERA_NEGARA
         </div>

         <!-- Proxy Grid -->
         PLACEHOLDER_PROXY_GROUP
      </div>

      <!-- Pagination -->
      <nav class="container mx-auto mt-10 mb-6 flex justify-center">
        <ul class="flex gap-4 glass-panel px-6 py-3 rounded-2xl shadow-lg">
          PLACEHOLDER_PAGE_BUTTON
        </ul>
      </nav>

    </main>

    <!-- Footer Actions -->
    <div class="fixed bottom-6 right-6 flex flex-col gap-3 z-40">
       <a href="${CONFIG.urls.donate}" target="_blank" class="group relative">
          <div class="absolute inset-0 bg-emerald-500 rounded-full blur opacity-40 group-hover:opacity-75 transition"></div>
          <button class="relative bg-slate-900 border border-emerald-500/50 text-emerald-400 p-3 rounded-full shadow-xl hover:scale-110 transition-all">
             <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-6 h-6"><path d="M10.464 8.746c.227-.18.497-.311.786-.394v2.795a2.252 2.252 0 0 1-.786-.393c-.394-.313-.546-.681-.546-1.004 0-.323.152-.691.546-1.004ZM12.75 15.662v-2.824c.347.085.664.228.921.421.427.32.579.686.579.991 0 .305-.152.671-.579.991a2.534 2.534 0 0 1-.921.42Z" /><path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25ZM12.75 6a.75.75 0 0 0-1.5 0v.816a3.836 3.836 0 0 0-1.72.756c-.712.566-1.112 1.35-1.112 2.178 0 .829.4 1.612 1.113 2.178.502.4 1.102.647 1.719.756v2.978a2.536 2.536 0 0 1-.921-.421l-.879-.66a.75.75 0 0 0-.9 1.2l.879.66c.533.4 1.169.645 1.821.75V18a.75.75 0 0 0 1.5 0v-.81a4.124 4.124 0 0 0 1.821-.749c.745-.559 1.179-1.344 1.179-2.191 0-.847-.434-1.632-1.179-2.191a4.122 4.122 0 0 0-1.821-.75V8.354c.29.082.559.213.786.393l.415.33a.75.75 0 0 0 .933-1.175l-.415-.33a3.836 3.836 0 0 0-1.719-.755V6Z" clip-rule="evenodd" /></svg>
          </button>
       </a>
       
       <button onclick="toggleWildcardsWindow()" class="PLACEHOLDER_API_READY bg-slate-900 border border-cyan-500/50 text-cyan-400 p-3 rounded-full shadow-xl hover:scale-110 transition-all hover:shadow-cyan-500/30">
         <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6">
           <path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
         </svg>
       </button>
    </div>

    <!-- MODALS (Windows) -->
    <div id="container-window" class="fixed inset-0 z-[60] hidden backdrop-blur-sm bg-slate-900/80 transition-opacity">
      
      <!-- Close Overlay -->
      <div class="absolute inset-0" onclick="toggleWindow()"></div>

      <!-- Output Modal -->
      <div id="output-window" class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[90%] max-w-md hidden transition-all duration-300 transform scale-95 opacity-0">
         <div class="glass-panel border border-slate-600 p-6 rounded-3xl shadow-2xl">
            <h3 id="container-window-info" class="text-xl font-bold text-white mb-6 text-center">Pilih Format</h3>
            
            <div class="grid grid-cols-2 gap-3 mb-4">
               <button onclick="copyToClipboardAsTarget('clash')" class="py-3 px-4 bg-slate-800 hover:bg-cyan-600 border border-slate-600 hover:border-cyan-500 rounded-xl transition-all text-sm font-semibold">Clash</button>
               <button onclick="copyToClipboardAsTarget('sfa')" class="py-3 px-4 bg-slate-800 hover:bg-cyan-600 border border-slate-600 hover:border-cyan-500 rounded-xl transition-all text-sm font-semibold">SFA</button>
               <button onclick="copyToClipboardAsTarget('bfr')" class="py-3 px-4 bg-slate-800 hover:bg-cyan-600 border border-slate-600 hover:border-cyan-500 rounded-xl transition-all text-sm font-semibold">BFR</button>
               <button onclick="copyToClipboardAsTarget('v2ray')" class="py-3 px-4 bg-slate-800 hover:bg-cyan-600 border border-slate-600 hover:border-cyan-500 rounded-xl transition-all text-sm font-semibold">V2Ray</button>
            </div>
            
            <button onclick="copyToClipboardAsRaw()" class="w-full py-3 mb-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 rounded-xl font-bold shadow-lg shadow-cyan-500/20">
               Salin Mentah (Raw)
            </button>
            
            <button onclick="toggleOutputWindow()" class="w-full py-2 text-slate-400 hover:text-white text-sm">Tutup</button>
         </div>
      </div>

      <!-- Wildcard Modal -->
      <div id="wildcards-window" class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[90%] max-w-md hidden">
         <div class="glass-panel border border-slate-600 p-6 rounded-3xl shadow-2xl">
            <h3 class="text-xl font-bold text-white mb-4">Kelola Domain</h3>
            
            <div class="flex gap-2 mb-4">
              <input id="new-domain-input" type="text" placeholder="Subdomain baru..." class="flex-1 bg-slate-800 border border-slate-600 rounded-xl px-4 py-2 focus:outline-none focus:border-cyan-500 text-white placeholder-slate-500">
              <button onclick="registerDomain()" class="bg-cyan-600 hover:bg-cyan-500 p-3 rounded-xl text-white transition shadow-lg">
                 <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="w-5 h-5"><path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" /></svg>
              </button>
            </div>

            <div id="container-domains" class="flex flex-col gap-2 max-h-60 overflow-y-auto scrollbar-hide">
               <!-- Domain list injected here -->
            </div>
            
            <button onclick="toggleWildcardsWindow()" class="w-full mt-4 py-2 text-slate-400 hover:text-white text-sm">Tutup</button>
         </div>
      </div>

    </div>

    <script>
      const rootDomain = "${CONFIG.serviceName}.${CONFIG.rootDomain}";
      const notification = document.getElementById("notification-badge");
      const windowContainer = document.getElementById("container-window");
      const windowInfoContainer = document.getElementById("container-window-info");
      let isDomainListFetched = false;
      let rawConfig = "";

      function showToast() {
         notification.classList.remove("translate-x-[150%]", "opacity-0");
         setTimeout(() => notification.classList.add("translate-x-[150%]", "opacity-0"), 3000);
      }

      function getDomainList() {
        if (isDomainListFetched) return;
        isDomainListFetched = true;
        const url = "https://" + rootDomain + "/api/v1/domains/get";
        fetch(url).then(async (res) => {
          const container = document.getElementById("container-domains");
          container.innerHTML = "";
          if (res.status == 200) {
            const json = await res.json();
            json.forEach(d => {
               const el = document.createElement("div");
               el.className = "px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-sm text-slate-300 break-all";
               el.innerText = d;
               container.appendChild(el);
            });
          }
        });
      }

      function registerDomain() {
        const input = document.getElementById("new-domain-input");
        const raw = input.value.toLowerCase();
        const domain = input.value + "." + rootDomain;
        if (!raw.match(/^[a-z0-9]+$/i)) return alert("Format domain salah!");
        
        windowInfoContainer.innerText = "Memproses...";
        fetch("https://" + rootDomain + "/api/v1/domains/put?domain=" + domain).then((res) => {
           if (res.status == 200) {
              input.value = "";
              isDomainListFetched = false;
              getDomainList();
              alert("Berhasil didaftarkan!");
           } else {
              alert("Gagal: " + res.status);
           }
        });
      }

      function copyToClipboard(text) {
        rawConfig = text;
        toggleOutputWindow();
      }

      function copyToClipboardAsRaw() {
        navigator.clipboard.writeText(rawConfig);
        toggleOutputWindow();
        showToast();
      }

      async function copyToClipboardAsTarget(target) {
        windowInfoContainer.innerText = "Mengkonversi...";
        const res = await fetch("${CONFIG.urls.converter}", {
          method: "POST",
          body: JSON.stringify({ url: rawConfig, format: target, template: "cf" }),
        });
        if (res.status == 200) {
          navigator.clipboard.writeText(await res.text());
          toggleOutputWindow();
          showToast();
        } else {
          windowInfoContainer.innerText = "Gagal!";
        }
      }

      function navigateTo(link) { window.location.href = link + window.location.search; }

      function toggleOutputWindow() {
        const win = document.getElementById("output-window");
        toggleWindow(win);
      }

      function toggleWildcardsWindow() {
        const win = document.getElementById("wildcards-window");
        toggleWindow(win);
        if(!win.classList.contains("hidden")) getDomainList();
      }

      function toggleWindow(specificWindow = null) {
        const bg = document.getElementById("container-window");
        
        if (bg.classList.contains("hidden")) {
           bg.classList.remove("hidden");
           if(specificWindow) {
              specificWindow.classList.remove("hidden");
              setTimeout(() => specificWindow.classList.remove("scale-95", "opacity-0"), 50);
           }
        } else {
           bg.classList.add("hidden");
           document.querySelectorAll("#container-window > div:not(.absolute)").forEach(el => {
              el.classList.add("hidden", "scale-95", "opacity-0");
           });
        }
      }

      function checkProxy() {
        for (let i = 0; ; i++) {
          const pingEl = document.getElementById("ping-"+i);
          if (!pingEl) break;
          
          // Parsing IP:Port logic preserved from original
          const target = pingEl.parentElement.parentElement.querySelector("p span").nextSibling.textContent.trim().split(":")[0] + ":" + 
                         pingEl.parentElement.parentElement.querySelector("p span").nextSibling.textContent.trim().split(":")[1];
          
          if (!target) continue;

          let isActive = false;
          fetch("https://${CONFIG.serviceName}.${CONFIG.rootDomain}/check?target=" + target)
            .then(async (res) => {
               if (isActive) return;
               const json = await res.json();
               if (res.status == 200 && json.proxyip === true) {
                  isActive = true;
                  pingEl.innerHTML = \`<span class="text-emerald-400">AKTIF \${json.delay}ms (\${json.colo})</span>\`;
               } else {
                  pingEl.innerHTML = \`<span class="text-rose-500">OFFLINE</span>\`;
               }
            }).catch(() => {
               pingEl.innerHTML = \`<span class="text-rose-500">ERROR</span>\`;
            });
        }
      }

      function checkGeoip() {
         fetch("https://" + rootDomain + "/api/v1/myip").then(async r => {
            const j = await r.json();
            document.getElementById("container-info-ip").innerText = j.ip;
            document.getElementById("container-info-country").innerText = j.country;
            document.getElementById("container-info-isp").innerText = j.asOrganization;
         });
      }

      window.onload = () => {
        checkGeoip();
        checkProxy();
        const observer = lozad(".lozad", { load: (el) => el.classList.remove("scale-95") });
        observer.observe();
      };
    </script>
  </body>
</html>
`;

export default {
  async fetch(request, env, ctx) {
    try {
      if (CONFIG.apiKey && CONFIG.apiEmail && CONFIG.accountID && CONFIG.zoneID) isApiReady = true;
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");
      
      if (upgradeHeader === "websocket") return await WebSocketManager.handleRequest(request);
      
      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
        
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
          if (!isApiReady) return new Response("API tidak siap", { status: 500 });
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
        
        if (apiPath.startsWith("/sub")) return await ConfigManager.generateSubscription(request);
        
        if (apiPath.startsWith("/myip")) {
          return new Response(JSON.stringify({
            ip: request.headers.get("cf-connecting-ipv6") || request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
            colo: request.headers.get("cf-ray")?.split("-")[1],
            ...request.cf,
          }), { headers: { ...CORS_HEADERS } });
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

