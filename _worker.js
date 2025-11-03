import { connect } from "cloudflare:sockets";
// import { createHash, createDecipheriv } from "node:crypto";
// import { Buffer } from "node:buffer";

// Variables
const rootDomain = "kaisaronline.web.id"; // Ganti dengan domain utama kalian
const serviceName = "premium"; // Ganti dengan nama workers kalian
const apiKey = "7qznGifWaacI0PtHzhVle_MUM5u-Aw5Xu2_que70"; // Ganti dengan Global API key kalian (https://dash.cloudflare.com/profile/api-tokens)
const apiEmail = "kopralwann03@gmail.com"; // Ganti dengan email yang kalian gunakan
const accountID = "03a4700138e72b9c57362b0423c93d98"; // Ganti dengan Account ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
const zoneID = "2addcdf0cab905ea6757695c04e8bd87"; // Ganti dengan Zone ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];

// Constant
const APP_DOMAIN = `${serviceName}.${rootDomain}`;
const PORTS = [443, 80];
const PROTOCOLS = [reverse("najort"), reverse("sselv"), reverse("ss")];
const KV_PROXY_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PROXY_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const PROXY_HEALTH_CHECK_API = "https://id1.foolvpn.me/api/v1/check";
const CONVERTER_URL = "https://api.foolvpn.me/convert";
const DONATE_LINK = "https://trakteer.id/dickymuliafiqri/tip";
const BAD_WORDS_LIST =
  "https://gist.githubusercontent.com/adierebel/a69396d79b787b84d89b45002cb37cd6/raw/6df5f8728b18699496ad588b3953931078ab9cf1/kata-kasar.txt";
const PROXY_PER_PAGE = 24;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Account management
const ACCOUNT_EXPIRY_DAYS = 30; // Masa aktif akun 30 hari

async function getKVProxyList(kvProxyUrl = KV_PROXY_URL) {
  if (!kvProxyUrl) {
    throw new Error("No KV Proxy URL Provided!");
  }

  const kvProxy = await fetch(kvProxyUrl);
  if (kvProxy.status == 200) {
    return await kvProxy.json();
  } else {
    return {};
  }
}

async function getProxyList(proxyBankUrl = PROXY_BANK_URL) {
  /**
   * Format:
   *
   * <IP>,<Port>,<Country ID>,<ORG>
   * Contoh:
   * 1.1.1.1,443,SG,Cloudflare Inc.
   */
  if (!proxyBankUrl) {
    throw new Error("No Proxy Bank URL Provided!");
  }

  const proxyBank = await fetch(proxyBankUrl);
  if (proxyBank.status == 200) {
    const text = (await proxyBank.text()) || "";

    const proxyString = text.split("\n").filter(Boolean);
    cachedProxyList = proxyString
      .map((entry) => {
        const [proxyIP, proxyPort, country, org] = entry.split(",");
        return {
          proxyIP: proxyIP || "Unknown",
          proxyPort: proxyPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }

  return cachedProxyList;
}

async function reverseProxy(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function getAllConfig(request, hostName, proxyList, page = 0) {
  const startIndex = PROXY_PER_PAGE * page;

  try {
    const uuid = crypto.randomUUID();

    // Build URI
    const uri = new URL(`${reverse("najort")}://${hostName}`);
    uri.searchParams.set("encryption", "none");
    uri.searchParams.set("type", "ws");
    uri.searchParams.set("host", hostName);

    // Build HTML
    const document = new Document(request);
    document.setTitle("Selamat Datang di <span class='font-bold text-3xl bg-gradient-to-r from-red-600 to-white bg-clip-text text-transparent'>Nusantara Proxy</span>");
    document.addInfo(`Total Server: ${proxyList.length}`);
    document.addInfo(`Halaman: ${page + 1}/${Math.ceil(proxyList.length / PROXY_PER_PAGE)}`);

    for (let i = startIndex; i < startIndex + PROXY_PER_PAGE; i++) {
      const proxy = proxyList[i];
      if (!proxy) break;

      const { proxyIP, proxyPort, country, org } = proxy;

      uri.searchParams.set("path", `/${proxyIP}-${proxyPort}`);

      const proxies = [];
      for (const port of PORTS) {
        uri.port = port.toString();
        uri.hash = `${i + 1} ${getFlagEmoji(country)} ${org} WS ${port == 443 ? "TLS" : "NTLS"} [${serviceName}]`;
        for (const protocol of PROTOCOLS) {
          // Special exceptions
          if (protocol === "ss") {
            uri.username = btoa(`none:${uuid}`);
            uri.searchParams.set(
              "plugin",
              `v2ray-plugin${
                port == 80 ? "" : ";tls"
              };mux=0;mode=websocket;path=/${proxyIP}-${proxyPort};host=${hostName}`
            );
          } else {
            uri.username = uuid;
            uri.searchParams.delete("plugin");
          }

          uri.protocol = protocol;
          uri.searchParams.set("security", port == 443 ? "tls" : "none");
          uri.searchParams.set("sni", port == 80 && protocol == reverse("sselv") ? "" : hostName);

          // Build VPN URI
          proxies.push(uri.toString());
        }
      }
      document.registerProxies(
        {
          proxyIP,
          proxyPort,
          country,
          org,
          index: i // Pass index for animation delay
        },
        proxies
      );
    }

    // Build pagination
    document.addPageButton("Sebelumnya", `/sub/${page > 0 ? page - 1 : 0}`, page <= 0);
    document.addPageButton("Selanjutnya", `/sub/${page + 1}`, (startIndex + PROXY_PER_PAGE) >= proxyList.length);

    return document.build();
  } catch (error) {
    return `Terjadi kesalahan saat membuat konfigurasi ${reverse("SSELV")}. ${error}`;
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // Gateway check
      if (apiKey && apiEmail && accountID && zoneID) {
        isApiReady = true;
      }

      // Handle proxy client
      if (upgradeHeader === "websocket") {
        const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (url.pathname.length == 3 || url.pathname.match(",")) {
          // Contoh: /ID, /SG, dll
          const proxyKeys = url.pathname.replace("/", "").toUpperCase().split(",");
          const proxyKey = proxyKeys[Math.floor(Math.random() * proxyKeys.length)];
          const kvProxy = await getKVProxyList();

          proxyIP = kvProxy[proxyKey][Math.floor(Math.random() * kvProxy[proxyKey].length)];

          return await websocketHandler(request);
        } else if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websocketHandler(request);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");

        // Queries
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
        let proxyList = (await getProxyList(proxyBankUrl)).filter((proxy) => {
          // Filter proxies by Country
          if (countrySelect) {
            return countrySelect.includes(proxy.country);
          }

          return true;
        });

        const result = getAllConfig(request, hostname, proxyList, pageIndex);
        return new Response(result, {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" },
        });
      } else if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const result = await checkProxyHealth(target[0], target[1] || "443");

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            ...CORS_HEADER_OPTIONS,
            "Content-Type": "application/json",
          },
        });
      } else if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (apiPath.startsWith("/domains")) {
          if (!isApiReady) {
            return new Response("Api not ready", {
              status: 500,
            });
          }

          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const name = url.searchParams.get("name");
            const selectedServers = url.searchParams.get("servers");
            const register = await cloudflareApi.registerDomain(domain, name, selectedServers);

            return new Response(register.toString(), {
              status: register,
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/account") {
            const domain = url.searchParams.get("domain");
            const accountInfo = await cloudflareApi.getAccountInfo(domain);
            return new Response(JSON.stringify(accountInfo), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          }
        } else if (apiPath.startsWith("/sub")) {
          const filterCC = url.searchParams.get("cc")?.split(",") || [];
          const filterPort = url.searchParams.get("port")?.split(",") || PORTS;
          const filterVPN = url.searchParams.get("vpn")?.split(",") || PROTOCOLS;
          const filterLimit = parseInt(url.searchParams.get("limit")) || 10;
          const filterFormat = url.searchParams.get("format") || "raw";
          const fillerDomain = url.searchParams.get("domain") || APP_DOMAIN;

          const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
          const proxyList = await getProxyList(proxyBankUrl)
            .then((proxies) => {
              // Filter CC
              if (filterCC.length) {
                return proxies.filter((proxy) => filterCC.includes(proxy.country));
              }
              return proxies;
            })
            .then((proxies) => {
              // shuffle result
              shuffleArray(proxies);
              return proxies;
            });

          const uuid = crypto.randomUUID();
          const result = [];
          for (const proxy of proxyList) {
            const uri = new URL(`${reverse("najort")}://${fillerDomain}`);
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
                    `v2ray-plugin${port == 80 ? "" : ";tls"};mux=0;mode=websocket;path=/${proxy.proxyIP}-${
                      proxy.proxyPort
                    };host=${APP_DOMAIN}`
                  );
                } else {
                  uri.username = uuid;
                }

                uri.searchParams.set("security", port == 443 ? "tls" : "none");
                uri.searchParams.set("sni", port == 80 && protocol == reverse("sselv") ? "" : APP_DOMAIN);
                uri.searchParams.set("path", `/${proxy.proxyIP}-${proxy.proxyPort}`);

                uri.hash = `${result.length + 1} ${getFlagEmoji(proxy.country)} ${proxy.org} WS ${
                  port == 443 ? "TLS" : "NTLS"
                } [${serviceName}]`;
                result.push(uri.toString());
              }
            }
          }

          let finalResult = "";
          switch (filterFormat) {
            case "raw":
              finalResult = result.join("\n");
              break;
            case "v2ray":
              finalResult = btoa(result.join("\n"));
              break;
            case "clash":
            case "sfa":
            case "bfr":
              const res = await fetch(CONVERTER_URL, {
                method: "POST",
                body: JSON.stringify({
                  url: result.join(","),
                  format: filterFormat,
                  template: "cf",
                }),
              });
              if (res.status == 200) {
                finalResult = await res.text();
              } else {
                return new Response(res.statusText, {
                  status: res.status,
                  headers: {
                    ...CORS_HEADER_OPTIONS,
                  },
                });
              }
              break;
          }

          return new Response(finalResult, {
            status: 200,
            headers: {
              ...CORS_HEADER_OPTIONS,
            },
          });
        } else if (apiPath.startsWith("/myip")) {
          return new Response(
            JSON.stringify({
              ip:
                request.headers.get("cf-connecting-ipv6") ||
                request.headers.get("cf-connecting-ip") ||
                request.headers.get("x-real-ip"),
              colo: request.headers.get("cf-ray")?.split("-")[1],
              ...request.cf,
            }),
            {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            }
          );
        }
      }

      const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
      return await reverseProxy(request, targetReverseProxy);
    } catch (err) {
      return new Response(`Terjadi kesalahan: ${err.toString()}`, {
        status: 500,
        headers: {
          ...CORS_HEADER_OPTIONS,
        },
      });
    }
  },
};

async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === reverse("najorT")) {
            protocolHeader = parseNajortHeader(chunk);
          } else if (protocol === reverse("SSELV")) {
            protocolHeader = parseSselvHeader(chunk);
          } else if (protocol === reverse("skcoswodahS")) {
            protocolHeader = parseSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              // return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log);
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              protocolHeader.version,
              log
            );
          }

          handleTCPOutBound(
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
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
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

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const najortDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (najortDelimiter[0] === 0x0d && najortDelimiter[1] === 0x0a) {
      if (najortDelimiter[2] === 0x01 || najortDelimiter[2] === 0x03 || najortDelimiter[2] === 0x7f) {
        if (najortDelimiter[3] === 0x01 || najortDelimiter[3] === 0x03 || najortDelimiter[3] === 0x04) {
          return reverse("najorT");
        }
      }
    }
  }

  const sselvDelimiter = new Uint8Array(buffer.slice(1, 17));
  // Hanya mendukung UUID v4
  if (arrayBufferToHex(sselvDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return reverse("SSELV");
  }

  return reverse("skcoswodahS"); // default
}

async function handleTCPOutBound(
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
    log(`connected to ${address}:${port}`);
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
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(targetAddress, targetPort, udpChunk, webSocket, responseHeader, log) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({
      hostname: targetAddress,
      port: targetPort,
    });

    log(`Connected to ${targetAddress}:${targetPort}`);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(udpChunk);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection to ${targetPort} aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound, error ${e.message}`);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function parseSsHeader(ssBuffer) {
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
      return {
        hasError: true,
        message: `Invalid addressType for ${reverse("skcoswodahS")}: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
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
    isUDP: portRemote == 53,
  };
}

function parseSselvHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
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
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

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

function parseNajortHeader(buffer) {
  const socks5DataBuffer = buffer.slice(58);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  let isUDP = false;
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
        "."
      );
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

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

// function parseSsemvHeader(buffer) {
//   const date = new Date(new Date().toLocaleString("en", { timeZone: "Asia/Jakarta" }));
//   console.log(`Date: ${date}`);
//   console.log(`First 16 bytes: ${arrayBufferToHex(buffer.slice(0, 17))}`);
//   console.log(`Remaining bytes: ${arrayBufferToHex(buffer.slice(17))}`);

//   // ===== KEY GENERATION =====
//   const userId = "3b670322-6ac1-41ec-9ff3-714245d41bf7";
//   const uuidConst = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

//   // Step 1: Generate AES key
//   const key = createHash("md5")
//     .update(userId + uuidConst)
//     .digest();
//   console.log(`KEY: ${key}`);

//   // Step 2: Generate Timestamp (current Unix time)
//   const timestamp = Math.floor(date.getTime() / 1000); // current timestamp in seconds

//   // Step 3: Generate IV from Timestamp
//   const x = Buffer.alloc(8);
//   x.writeBigUInt64BE(BigInt(timestamp)); // 8-byte timestamp (Big Endian)
//   const iv_source = Buffer.concat([x, x, x, x]);
//   const iv = createHash("md5").update(iv_source).digest();
//   console.log(`IV: ${iv}`);

//   // Step 4: Decrypt using AES-128-CFB
//   const decipher = createDecipheriv("aes-128-cfb", key, iv);
//   const decrypted = Buffer.concat([decipher.update(buffer.slice(17)), decipher.final()]);

//   console.log(`Decrypted Header: ${decrypted.toString("hex")}`);
// }

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkProxyHealth(proxyIP, proxyPort) {
  const req = await fetch(`${PROXY_HEALTH_CHECK_API}?ip=${proxyIP}:${proxyPort}`);
  return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  let currentIndex = array.length;

  // While there remain elements to shuffle...
  while (currentIndex != 0) {
    // Pick a remaining element...
    let randomIndex = Math.floor(Math.random() * currentIndex);
    currentIndex--;

    // And swap it with the current element.
    [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
  }
}

async function generateHashFromText(text) {
  const msgUint8 = new TextEncoder().encode(text); // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest("MD5", msgUint8); // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(""); // convert bytes to hex string

  return hashHex;
}

function reverse(s) {
  return s.split("").reverse().join("");
}

// ===== PERBAIKAN DI FUNGSI INI (DARI PREV. TURN) =====
function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints); // Diubah dari ...points
}
// ===================================

// CloudflareApi Class
class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${apiKey}`;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.apiKey = apiKey;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
    };
  }

  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();

      return respJson.result.filter((data) => data.service == serviceName).map((data) => data.hostname);
    }

    return [];
  }

  async registerDomain(domain, name, selectedServers) {
    domain = domain.toLowerCase();
    const registeredDomains = await this.getDomainList();

    if (!domain.endsWith(rootDomain)) return 400;
    if (registeredDomains.includes(domain)) return 409;

    try {
      const domainTest = await fetch(`https://${domain.replaceAll("." + APP_DOMAIN, "")}`);
      if (domainTest.status == 530) return domainTest.status;

      const badWordsListRes = await fetch(BAD_WORDS_LIST);
      if (badWordsListRes.status == 200) {
        const badWordsList = (await badWordsListRes.text()).split("\n");
        for (const badWord of badWordsList) {
          if (domain.includes(badWord.toLowerCase())) {
            return 403;
          }
        }
      } else {
        return 403;
      }
    } catch (e) {
      return 400;
    }

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({
        environment: "production",
        hostname: domain,
        service: serviceName,
        zone_id: this.zoneID,
        metadata: {
          name: name,
          servers: selectedServers,
          created: new Date().toISOString(),
          expires: new Date(Date.now() + ACCOUNT_EXPIRY_DAYS * 24 * 60 * 60 * 1000).toISOString()
        }
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
  
  async getAccountInfo(domain) {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();
      const domainData = respJson.result.find((data) => data.hostname === domain);
      
      if (domainData && domainData.metadata) {
        return {
          name: domainData.metadata.name || "Unknown",
          servers: domainData.metadata.servers || [],
          created: domainData.metadata.created || new Date().toISOString(),
          expires: domainData.metadata.expires || new Date().toISOString()
        };
      }
    }

    return null;
  }
}

// ==================================================================================
// =================== PERUBAHAN TAMPILAN WEB DIMULAI DARI SINI ===================
// ==================================================================================

// HTML page base
/**
 * Tampilan web diubah total menjadi tema Indonesia yang khas.
 * Menggunakan warna merah-putih seperti bendera Indonesia.
 * Menambahkan fitur pemilihan server yang terhubung dengan akun.
 * Menambahkan masa aktif akun.
 * Memperbaiki fitur pencarian server agar berfungsi dengan baik.
 *
 * PERUBAHAN v5 (INDONESIAN THEME):
 * - Palet warna merah-putih seperti bendera Indonesia.
 * - Bahasa Indonesia seluruh antarmuka.
 * - Fitur pemilihan server dengan checkbox.
 * - Sistem akun dengan masa aktif.
 * - Pencarian server yang berfungsi dengan baik.
 * - Desain dengan elemen-elemen budaya Indonesia.
 * - Animasi yang lebih smooth.
 * - Responsive design yang lebih baik.
 */
let baseHTML = `
<!DOCTYPE html>
<html lang="id" id="html" class="scroll-smooth">
  <head>
    <meta charset="UTF-g" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Nusantara Proxy - Server Proxy Indonesia</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    
    <style>
      /* For Webkit-based browsers (Chrome, Safari and Opera) */
      .scrollbar-hide::-webkit-scrollbar {
          display: none;
      }

      /* For IE, Edge and Firefox */
      .scrollbar-hide {
          -ms-overflow-style: none;  /* IE and Edge */
          scrollbar-width: none;  /* Firefox */
      }

      body {
        font-family: 'Plus Jakarta Sans', sans-serif;
      }

      /* Custom style for AOS */
      [data-aos] {
        transition-property: transform, opacity;
      }
      
      /* Indonesian flag gradient animation */
      @keyframes indonesiaFlag {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
      }
      
      .indonesia-gradient {
        background: linear-gradient(-45deg, #ff0000, #ffffff, #ff0000, #ffffff);
        background-size: 400% 400%;
        animation: indonesiaFlag 15s ease infinite;
      }
      
      /* Glass morphism effect */
      .glass {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
      }
      
      .dark .glass {
        background: rgba(0, 0, 0, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      
      /* Custom checkbox */
      .custom-checkbox {
        appearance: none;
        width: 20px;
        height: 20px;
        border: 2px solid #e11d48;
        border-radius: 4px;
        transition: all 0.2s;
        position: relative;
        cursor: pointer;
      }
      
      .custom-checkbox:checked {
        background-color: #e11d48;
        border-color: #e11d48;
      }
      
      .custom-checkbox:checked::after {
        content: '✓';
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        color: white;
        font-size: 14px;
        font-weight: bold;
      }
      
      /* Loading animation */
      .loader {
        border: 3px solid rgba(225, 29, 72, 0.2);
        border-radius: 50%;
        border-top: 3px solid #e11d48;
        width: 20px;
        height: 20px;
        animation: spin 1s linear infinite;
      }
      
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      
      /* Batik pattern background */
      .batik-pattern {
        background-color: #fef2f2;
        background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23e11d48' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
      }
      
      .dark .batik-pattern {
        background-color: #1f2937;
        background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23e11d48' fill-opacity='0.1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
      }
      
      /* Server card hover effect */
      .server-card {
        transition: all 0.3s ease;
        transform-origin: center;
      }
      
      .server-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(225, 29, 72, 0.2);
      }
      
      .server-card.selected {
        border: 2px solid #e11d48;
        background-color: rgba(225, 29, 72, 0.05);
      }
      
      /* Auto-complete dropdown */
      .autocomplete-dropdown {
        max-height: 200px;
        overflow-y: auto;
      }
      
      /* Floating animation */
      @keyframes float {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
        100% { transform: translateY(0px); }
      }
      
      .float-animation {
        animation: float 3s ease-in-out infinite;
      }
      
      /* Pulse animation */
      @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
      }
      
      .pulse-animation {
        animation: pulse 2s ease-in-out infinite;
      }
      
      /* Status indicator */
      .status-online {
        position: relative;
      }
      
      .status-online::before {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        animation: pulse 2s infinite;
      }
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>
      tailwind.config = {
        darkMode: 'selector',
        theme: {
          extend: {
            fontFamily: {
              sans: ['Plus Jakarta Sans', 'sans-serif'],
            },
            animation: {
              'indonesia-flag': 'indonesiaFlag 15s ease infinite',
              'float': 'float 3s ease-in-out infinite',
              'pulse': 'pulse 2s ease-in-out infinite',
            },
            colors: {
              'indonesia-red': '#e11d48',
              'indonesia-white': '#ffffff',
            }
          },
        },
      }
    </script>
  </head>
  <body class="batik-pattern dark:bg-gray-900 text-gray-800 dark:text-gray-200 selection:bg-indonesia-red selection:text-white">

    <!-- Navigation Header -->
    <header data-aos="fade-down" class="sticky top-0 z-50 glass shadow-lg">
      <div class="container mx-auto px-6 py-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-4">
            <div class="indonesia-gradient text-white p-2 rounded-lg float-animation">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h1 id="container-title" class="text-xl font-bold text-gray-800 dark:text-white">
              PLACEHOLDER_JUDUL
            </h1>
          </div>
          
          <div class="flex items-center space-x-4">
            <div class="hidden md:flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
              <div id="container-info-ip" class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <span>IP: ...</span>
              </div>
              <div id="container-info-country" class="flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>Negara: ...</span>
              </div>
            </div>
            
            <button onclick="toggleDarkMode()" class="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors" title="Ganti Mode">
              <svg id="dark-mode-icon" xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </header>

    <!-- Hero Section -->
    <section class="indonesia-gradient text-white py-16 relative overflow-hidden">
      <div class="absolute inset-0 bg-black opacity-20"></div>
      <div class="container mx-auto px-6 relative z-10">
        <div class="flex flex-col md:flex-row items-center justify-between">
          <div class="md:w-1/2 mb-8 md:mb-0" data-aos="fade-right">
            <h2 class="text-4xl md:text-5xl font-bold mb-4">Server Proxy Terbaik</h2>
            <p class="text-xl mb-6 text-red-100">Layanan proxy cepat, aman, andal untuk kebutuhan internet Anda. Dukungan penuh untuk server Indonesia.</p>
            <div class="flex flex-wrap gap-4 mb-8">
              <div class="bg-white/20 backdrop-blur-sm rounded-lg p-4 pulse-animation">
                <div class="text-3xl font-bold" id="server-count">...</div>
                <div class="text-sm">Server Aktif</div>
              </div>
              <div class="bg-white/20 backdrop-blur-sm rounded-lg p-4 pulse-animation" style="animation-delay: 0.5s">
                <div class="text-3xl font-bold" id="country-count">...</div>
                <div class="text-sm">Negara</div>
              </div>
              <div class="bg-white/20 backdrop-blur-sm rounded-lg p-4 pulse-animation" style="animation-delay: 1s">
                <div class="text-3xl font-bold">99.9%</div>
                <div class="text-sm">Uptime</div>
              </div>
            </div>
            <div class="flex flex-wrap gap-3">
              <button onclick="scrollToServers()" class="px-6 py-3 bg-white text-indonesia-red font-semibold rounded-lg hover:bg-gray-100 transition-all transform hover:scale-105">
                Jelajahi Server
              </button>
              <button onclick="toggleWildcardsWindow()" class="px-6 py-3 bg-indonesia-red text-white font-semibold rounded-lg hover:bg-red-700 transition-all transform hover:scale-105 PLACEHOLDER_API_READY">
                Buat Akun
              </button>
            </div>
          </div>
          <div class="md:w-1/2" data-aos="fade-left">
            <div class="relative">
              <img src="https://picsum.photos/seed/indonesia-proxy/600/400.jpg" alt="Server Proxy Indonesia" class="rounded-lg shadow-2xl">
              <div class="absolute -bottom-6 -right-6 bg-white dark:bg-gray-800 rounded-lg shadow-xl p-4 float-animation">
                <div class="flex items-center space-x-2">
                  <div class="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                  <span class="text-sm font-medium text-gray-800 dark:text-white">Semua Sistem Beroperasi</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Advanced Search Section -->
    <section class="bg-white dark:bg-gray-800 py-8 shadow-md">
      <div class="container mx-auto px-6">
        <div class="max-w-4xl mx-auto">
          <h3 class="text-2xl font-bold text-center mb-6 text-gray-800 dark:text-white">Temukan Server Sempurna Anda</h3>
          
          <div class="bg-gray-50 dark:bg-gray-700 rounded-xl p-6 shadow-lg">
            <!-- Search Bar with Auto-complete -->
            <div class="relative mb-6">
              <input 
                type="text" 
                id="search-input" 
                placeholder="Cari berdasarkan negara, IP, atau provider..." 
                class="w-full pl-12 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indonesia-red"
                autocomplete="off"
              >
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 absolute left-4 top-3.5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              
              <!-- Auto-complete Dropdown -->
              <div id="autocomplete-dropdown" class="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg shadow-lg hidden autocomplete-dropdown z-20">
                <!-- Auto-complete items will be inserted here -->
              </div>
            </div>
            
            <!-- Quick Filters -->
            <div class="flex flex-wrap gap-2 mb-6">
              <button onclick="setQuickFilter('indonesia')" class="quick-filter px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium hover:bg-indonesia-red hover:text-white transition-all">
                🇮🇩 Indonesia
              </button>
              <button onclick="setQuickFilter('asia')" class="quick-filter px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium hover:bg-indonesia-red hover:text-white transition-all">
                🌏 Asia
              </button>
              <button onclick="setQuickFilter('europe')" class="quick-filter px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium hover:bg-indonesia-red hover:text-white transition-all">
                🌍 Eropa
              </button>
              <button onclick="setQuickFilter('america')" class="quick-filter px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium hover:bg-indonesia-red hover:text-white transition-all">
                🌎 Amerika
              </button>
              <button onclick="clearFilters()" class="px-4 py-2 bg-gray-200 dark:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-full text-sm font-medium hover:bg-red-500 hover:text-white transition-all">
                ✖ Hapus
              </button>
            </div>
            
            <!-- Advanced Options -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Protokol</label>
                <select id="protocol-select" class="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indonesia-red">
                  <option value="all">Semua Protokol</option>
                  <option value="vless">VLESS</option>
                  <option value="trojan">Trojan</option>
                  <option value="ss">Shadowsocks</option>
                </select>
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Keamanan</label>
                <select id="security-select" class="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indonesia-red">
                  <option value="all">Semua Keamanan</option>
                  <option value="tls">TLS</option>
                  <option value="none">Tanpa Keamanan</option>
                </select>
              </div>
              
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Urutkan</label>
                <select id="sort-select" class="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-indonesia-red">
                  <option value="default">Default</option>
                  <option value="name">Nama</option>
                  <option value="country">Negara</option>
                  <option value="speed">Kecepatan</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Main Content -->
    <main class="container mx-auto px-6 py-8" id="servers-section">
      <!-- Server Selection Info -->
      <section class="mb-6 bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 border border-blue-200 dark:border-blue-800">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-3">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span class="text-sm text-blue-800 dark:text-blue-200">Pilih server yang ingin Anda hubungkan dengan akun Anda</span>
          </div>
          <div class="flex items-center space-x-2">
            <span class="text-sm text-gray-600 dark:text-gray-400">Terpilih:</span>
            <span id="selected-count" class="text-sm font-bold text-indonesia-red">0</span>
          </div>
        </div>
      </section>
      
      <!-- Server Grid -->
      <section class="mb-12">
        <div class="flex items-center justify-between mb-6">
          <h3 class="text-2xl font-bold text-gray-800 dark:text-white">Server Tersedia</h3>
          <div class="text-sm text-gray-600 dark:text-gray-400">
            PLACEHOLDER_INFO
          </div>
        </div>
        
        <div id="proxy-grid-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          PLACEHOLDER_PROXY_GROUP
        </div>
      </section>

      <!-- Pagination -->
      <nav id="container-pagination" class="flex justify-center" data-aos="fade-up">
        <ul class="flex space-x-2">
          PLACEHOLDER_PAGE_BUTTON
        </ul>
      </nav>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-100 dark:bg-gray-800 py-12 mt-16">
      <div class="container mx-auto px-6">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <h4 class="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Nusantara Proxy</h4>
            <p class="text-gray-600 dark:text-gray-400">Layanan proxy premium untuk semua kebutuhan internet Anda. Cepat, aman, dan andal.</p>
          </div>
          
          <div>
            <h4 class="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Tautan Cepat</h4>
            <ul class="space-y-2">
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Tentang Kami</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Harga</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Dokumentasi</a></li>
            </ul>
          </div>
          
          <div>
            <h4 class="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Dukungan</h4>
            <ul class="space-y-2">
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Pusat Bantuan</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Hubungi Kami</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Status</a></li>
            </ul>
          </div>
          
          <div>
            <h4 class="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Legal</h4>
            <ul class="space-y-2">
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Kebijakan Privasi</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Syarat & Ketentuan</a></li>
              <li><a href="#" class="text-gray-600 dark:text-gray-400 hover:text-indonesia-red transition-colors">Kebijakan Cookie</a></li>
            </ul>
          </div>
        </div>
        
        <div class="border-t border-gray-200 dark:border-gray-700 mt-8 pt-8 text-center">
          <p class="text-gray-600 dark:text-gray-400">&copy; 2025 ${serviceName}.${rootDomain}. Hak Cipta Dilindungi.</p>
        </div>
      </div>
    </footer>

    <!-- Floating Action Buttons -->
    <div class="fixed bottom-6 right-6 flex flex-col space-y-3">
      <a href="${DONATE_LINK}" target="_blank" title="Donasi" class="bg-indonesia-red text-white rounded-full p-3 shadow-lg hover:bg-red-700 transition-all hover:scale-110 float-animation">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </a>
      
      <button onclick="toggleWildcardsWindow()" title="Buat Akun" class="bg-indonesia-red text-white rounded-full p-3 shadow-lg hover:bg-red-700 transition-all hover:scale-110 float-animation PLACEHOLDER_API_READY" style="animation-delay: 0.5s">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
        </svg>
      </button>
      
      <button onclick="scrollToTop()" title="Kembali ke Atas" class="bg-gray-500 text-white rounded-full p-3 shadow-lg hover:bg-gray-600 transition-all hover:scale-110 float-animation" style="animation-delay: 1s">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18" />
        </svg>
      </button>
    </div>

    <!-- Notification -->
    <div
      id="notification-badge"
      class="fixed z-50 opacity-0 transition-all ease-in-out duration-300 top-24 right-6 p-4 max-w-sm bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 flex items-center gap-x-4"
    >
      <div class="shrink-0">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
      <div>
        <div class="text-md font-bold text-green-600">Berhasil!</div>
        <p class="text-sm text-gray-600 dark:text-gray-400">Konfigurasi berhasil disalin!</p>
      </div>
    </div>

    <!-- Modal Window -->
    <div id="container-window" class="hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-sm">
      <div data-aos="zoom-in" data-aos-duration="300" class="fixed z-50 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[90%] max-w-md p-6 bg-white dark:bg-gray-800 rounded-xl shadow-2xl">
        <p id="container-window-info" class="text-center w-full text-lg font-medium text-gray-800 dark:text-white mb-4"></p>
        
        <!-- Output Window -->
        <div id="output-window" class="w-full h-full flex flex-col gap-4 text-center rounded-md hidden">
          <div class="grid grid-cols-2 gap-3">
            <button onclick="copyToClipboardAsTarget('clash')" class="p-3 rounded-lg bg-indonesia-red text-white font-semibold transition-all hover:bg-red-700 hover:scale-105">
              Clash
            </button>
            <button onclick="copyToClipboardAsTarget('sfa')" class="p-3 rounded-lg bg-indonesia-red text-white font-semibold transition-all hover:bg-red-700 hover:scale-105">
              SFA
            </button>
            <button onclick="copyToClipboardAsTarget('bfr')" class="p-3 rounded-lg bg-indonesia-red text-white font-semibold transition-all hover:bg-red-700 hover:scale-105">
              BFR
            </button>
            <button onclick="copyToClipboardAsTarget('v2ray')" class="p-3 rounded-lg bg-gray-500 text-white font-semibold transition-all hover:bg-gray-600 hover:scale-105">
              V2Ray/Xray
            </button>
          </div>
          <button onclick="copyToClipboardAsRaw()" class="w-full p-3 border-2 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 font-semibold rounded-lg transition-all hover:bg-gray-100 dark:hover:bg-gray-700">
            Raw
          </button>
          <button onclick="toggleOutputWindow()" class="w-full p-3 border-2 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 font-semibold rounded-lg transition-all hover:bg-gray-100 dark:hover:bg-gray-700">
            Tutup
          </button>
        </div>
        
        <!-- Wildcards Window -->
        <div id="wildcards-window" class="w-full h-full flex flex-col gap-4 rounded-md hidden">
          <h3 class="text-xl font-bold text-gray-800 dark:text-white mb-4">Buat Akun Baru</h3>
          
          <!-- Account Creation Form -->
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Nama Lengkap</label>
              <input
                id="account-name-input"
                type="text"
                placeholder="Masukkan nama lengkap"
                class="w-full px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-indonesia-red border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-white"
              />
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Subdomain</label>
              <div class="flex w-full h-full gap-2">
                <input
                  id="new-domain-input"
                  type="text"
                  placeholder="namamu"
                  class="flex-grow w-full h-full px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-indonesia-red border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-white"
                />
                <span class="flex items-center px-3 bg-gray-100 dark:bg-gray-600 rounded-lg text-gray-600 dark:text-gray-300">.${rootDomain}</span>
              </div>
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Server Terpilih</label>
              <div class="bg-gray-100 dark:bg-gray-700 rounded-lg p-3 min-h-[60px]">
                <div id="selected-servers-display" class="text-sm text-gray-600 dark:text-gray-400">
                  Belum ada server yang dipilih
                </div>
              </div>
            </div>
            
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Masa Aktif</label>
              <div class="bg-indonesia-red/10 border border-indonesia-red/30 rounded-lg p-3">
                <div class="flex items-center justify-between">
                  <span class="text-sm font-medium text-indonesia-red">${ACCOUNT_EXPIRY_DAYS} Hari</span>
                  <span class="text-xs text-gray-600 dark:text-gray-400">Mulai dari hari pendaftaran</span>
                </div>
              </div>
            </div>
            
            <button
              onclick="registerDomain()"
              class="w-full p-3 rounded-lg bg-indonesia-red text-white font-semibold transition-all hover:bg-red-700 hover:scale-105"
            >
              Buat Akun Sekarang
            </button>
          </div>
          
          <div class="border-t border-gray-200 dark:border-gray-600 pt-4">
            <h4 class="text-lg font-semibold text-gray-800 dark:text-white mb-3">Akun Saya</h4>
            <div class="h-48 rounded-md bg-gray-100 dark:bg-gray-700 p-4 overflow-y-auto">
              <div id="container-domains" class="w-full h-full flex flex-col gap-2 text-gray-800 dark:text-white">
                <!-- Domains will be listed here -->
              </div>
            </div>
          </div>
          
          <button onclick="toggleWildcardsWindow()" class="w-full p-3 border-2 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg transition-all hover:bg-gray-100 dark:hover:bg-gray-700">
            Tutup
          </button>
        </div>
      </div>
    </div>

    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
      // Shared
      const rootDomain = "${serviceName}.${rootDomain}";
      const notification = document.getElementById("notification-badge");
      const windowContainer = document.getElementById("container-window");
      const windowInfoContainer = document.getElementById("container-window-info");
      const converterUrl = "${CONVERTER_URL}";
      
      // State
      let isDomainListFetched = false;
      let rawConfig = "";
      let selectedCountries = [];
      let searchTerm = "";
      let sortBy = "default";
      let selectedProtocol = "all";
      let selectedSecurity = "all";
      let serverData = [];
      let selectedServers = new Set();
      
      // Initialize
      window.onload = () => {
        AOS.init({
          duration: 600,
          easing: 'ease-out',
          once: true,
        });
        
        checkGeoip();
        checkProxy();
        updateServerStats();
        setDarkModeIcon();
        setupAutoComplete();
        
        // Event listeners
        document.getElementById('search-input').addEventListener('input', handleSearch);
        document.getElementById('protocol-select').addEventListener('change', handleFilterChange);
        document.getElementById('security-select').addEventListener('change', handleFilterChange);
        document.getElementById('sort-select').addEventListener('change', handleFilterChange);
        
        // Auto-fill name from subdomain
        document.getElementById('new-domain-input').addEventListener('input', (e) => {
          const nameInput = document.getElementById('account-name-input');
          if (!nameInput.value) {
            nameInput.value = e.target.value;
          }
        });
        
        const observer = lozad(".lozad", {
          load: function (el) {
            el.classList.remove("scale-95");
          },
        });
        observer.observe();
      };
      
      // Auto-complete setup
      function setupAutoComplete() {
        const searchInput = document.getElementById('search-input');
        const dropdown = document.getElementById('autocomplete-dropdown');
        
        searchInput.addEventListener('focus', () => {
          if (searchInput.value.length > 0) {
            showAutoComplete(searchInput.value);
          }
        });
        
        searchInput.addEventListener('blur', () => {
          setTimeout(() => {
            dropdown.classList.add('hidden');
          }, 200);
        });
      }
      
      function showAutoComplete(query) {
        const dropdown = document.getElementById('autocomplete-dropdown');
        const filteredServers = serverData.filter(server => 
          server.country.toLowerCase().includes(query.toLowerCase()) ||
          server.org.toLowerCase().includes(query.toLowerCase()) ||
          server.proxyIP.includes(query)
        );
        
        if (filteredServers.length > 0 && query.length > 0) {
          dropdown.innerHTML = filteredServers.slice(0, 5).map(server => \`
            <div class="px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer flex items-center space-x-2" onclick="selectServer('\${server.proxyIP}')">
              <img width="20" src="https://hatscripts.github.io/circle-flags/flags/\${server.country.toLowerCase()}.svg" />
              <span class="text-sm">\${server.org} - \${server.country}</span>
            </div>
          \`).join('');
          dropdown.classList.remove('hidden');
        } else {
          dropdown.classList.add('hidden');
        }
      }
      
      function selectServer(ip) {
        document.getElementById('search-input').value = ip;
        document.getElementById('autocomplete-dropdown').classList.add('hidden');
        handleSearch();
      }
      
      function handleSearch() {
        const query = document.getElementById('search-input').value.toLowerCase();
        searchTerm = query;
        
        if (query.length > 0) {
          showAutoComplete(query);
        } else {
          document.getElementById('autocomplete-dropdown').classList.add('hidden');
        }
        
        filterAndDisplayServers();
      }
      
      function handleFilterChange() {
        selectedProtocol = document.getElementById('protocol-select').value;
        selectedSecurity = document.getElementById('security-select').value;
        sortBy = document.getElementById('sort-select').value;
        filterAndDisplayServers();
      }
      
      function setQuickFilter(filter) {
        // Reset all filters
        clearFilters();
        
        // Apply quick filter
        switch(filter) {
          case 'indonesia':
            selectedCountries = ['ID'];
            break;
          case 'asia':
            selectedCountries = ['ID', 'SG', 'JP', 'KR', 'HK', 'TH', 'MY', 'IN'];
            break;
          case 'europe':
            selectedCountries = ['GB', 'DE', 'FR', 'NL', 'RU', 'IT', 'ES', 'CH'];
            break;
          case 'america':
            selectedCountries = ['US', 'CA', 'BR', 'MX', 'AR', 'CL'];
            break;
        }
        
        // Update UI
        document.getElementById('sort-select').value = sortBy;
        filterAndDisplayServers();
      }
      
      function clearFilters() {
        selectedCountries = [];
        searchTerm = "";
        selectedProtocol = "all";
        selectedSecurity = "all";
        sortBy = "default";
        
        document.getElementById('search-input').value = "";
        document.getElementById('protocol-select').value = "all";
        document.getElementById('security-select').value = "all";
        document.getElementById('sort-select').value = "default";
        
        // Reset quick filter buttons
        document.querySelectorAll('.quick-filter').forEach(btn => {
          btn.classList.remove('bg-indonesia-red', 'text-white');
          btn.classList.add('bg-gray-200', 'dark:bg-gray-600', 'text-gray-800', 'dark:text-gray-200');
        });
      }
      
      function updateServerStats() {
        const serverCount = document.getElementById('server-count');
        const countryCount = document.getElementById('country-count');
        
        // Get server count from the page
        const proxyElements = document.querySelectorAll('[data-proxy]');
        serverCount.textContent = proxyElements.length;
        
        // Get unique countries
        const countries = new Set();
        proxyElements.forEach(el => {
          const country = el.getAttribute('data-country');
          if (country) countries.add(country);
        });
        countryCount.textContent = countries.size;
      }
      
      function filterAndDisplayServers() {
        const proxyElements = document.querySelectorAll('[data-proxy]');
        const filteredElements = Array.from(proxyElements).filter(el => {
          const country = el.getAttribute('data-country');
          const name = el.getAttribute('data-name').toLowerCase();
          const ip = el.getAttribute('data-ip');
          
          // Country filter
          if (selectedCountries.length > 0 && !selectedCountries.includes(country)) {
            return false;
          }
          
          // Search filter
          if (searchTerm && !name.includes(searchTerm) && !ip.includes(searchTerm)) {
            return false;
          }
          
          return true;
        });
        
        // Sort
        if (sortBy === 'name') {
          filteredElements.sort((a, b) => {
            return a.getAttribute('data-name').localeCompare(b.getAttribute('data-name'));
          });
        } else if (sortBy === 'country') {
          filteredElements.sort((a, b) => {
            return a.getAttribute('data-country').localeCompare(b.getAttribute('data-country'));
          });
        } else if (sortBy === 'speed') {
          filteredElements.sort((a, b) => {
            const speedA = parseInt(a.getAttribute('data-speed')) || 999;
            const speedB = parseInt(b.getAttribute('data-speed')) || 999;
            return speedA - speedB;
          });
        }
        
        // Hide all elements first
        proxyElements.forEach(el => {
          el.style.display = 'none';
        });
        
        // Show filtered elements
        filteredElements.forEach(el => {
          el.style.display = '';
        });
        
        // Update count
        document.getElementById('server-count').textContent = filteredElements.length;
      }
      
      function toggleServerSelection(serverId) {
        const checkbox = document.getElementById(\`server-checkbox-\${serverId}\`);
        const card = document.getElementById(\`server-card-\${serverId}\`);
        
        if (checkbox.checked) {
          selectedServers.add(serverId);
          card.classList.add('selected');
        } else {
          selectedServers.delete(serverId);
          card.classList.remove('selected');
        }
        
        updateSelectedServersDisplay();
      }
      
      function updateSelectedServersDisplay() {
        const countElement = document.getElementById('selected-count');
        const displayElement = document.getElementById('selected-servers-display');
        
        countElement.textContent = selectedServers.size;
        
        if (selectedServers.size === 0) {
          displayElement.textContent = 'Belum ada server yang dipilih';
        } else {
          const serverNames = Array.from(selectedServers).map(id => {
            const card = document.getElementById(\`server-card-\${id}\`);
            return card ? card.getAttribute('data-name') : id;
          });
          displayElement.textContent = serverNames.join(', ');
        }
      }
      
      function scrollToServers() {
        document.getElementById('servers-section').scrollIntoView({ behavior: 'smooth' });
      }
      
      function scrollToTop() {
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      }
      
      function getDomainList() {
        if (isDomainListFetched) return;
        isDomainListFetched = true;

        windowInfoContainer.innerText = "Mengambil data...";
        const domainListContainer = document.getElementById("container-domains");
        domainListContainer.innerHTML = '<div class="flex justify-center"><div class="loader"></div></div>';

        const url = "https://" + rootDomain + "/api/v1/domains/get";
        const res = fetch(url).then(async (res) => {
          domainListContainer.innerHTML = "";

          if (res.status == 200) {
            windowInfoContainer.innerText = "Akun Saya";
            const respJson = await res.json();
            if (respJson.length === 0) {
              domainListContainer.innerHTML = '<p class="text-center text-gray-500 dark:text-gray-400">Belum ada akun yang dibuat.</p>';
              return;
            }
            for (const domain of respJson) {
              // Get account info
              const accountUrl = "https://" + rootDomain + "/api/v1/domains/account?domain=" + domain;
              const accountRes = fetch(accountUrl).then(async (accountRes) => {
                let accountInfo = { name: "Unknown", expires: "Unknown" };
                if (accountRes.status == 200) {
                  accountInfo = await accountRes.json();
                }
                
                const domainElement = document.createElement("div");
                const expiryDate = new Date(accountInfo.expires);
                const today = new Date();
                const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
                const isExpired = daysLeft < 0;
                
                domainElement.classList.add("p-3", "bg-gray-100", "dark:bg-gray-600", "rounded-md", "font-medium", "flex", "justify-between", "items-center");
                domainElement.innerHTML = \`
                  <div class="flex-1">
                    <div class="font-semibold">\${accountInfo.name}</div>
                    <div class="text-xs text-gray-600 dark:text-gray-400">\${domain}</div>
                    <div class="text-xs \${isExpired ? 'text-red-500' : daysLeft <= 7 ? 'text-yellow-500' : 'text-green-500'}">
                      \${isExpired ? 'Kadaluarsa' : daysLeft + ' hari lagi'}
                    </div>
                  </div>
                  <div class="flex space-x-2">
                    <button onclick="copyToClipboard('\${domain}')" class="text-indonesia-red hover:text-red-600" title="Salin">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                \`;
                domainListContainer.appendChild(domainElement);
              });
            }
          } else {
            windowInfoContainer.innerText = "Gagal!";
            domainListContainer.innerHTML = '<p class="text-center text-red-500">Gagal mengambil akun.</p>';
          }
        });
      }

      function registerDomain() {
        const nameInput = document.getElementById("account-name-input");
        const domainInputElement = document.getElementById("new-domain-input");
        const rawDomain = domainInputElement.value.toLowerCase().trim();
        const name = nameInput.value.trim();
        
        if (!rawDomain) {
            showWindowInfo("Subdomain tidak boleh kosong!");
            return;
        }
        
        if (!name) {
            showWindowInfo("Nama tidak boleh kosong!");
            return;
        }
        
        if (selectedServers.size === 0) {
            showWindowInfo("Pilih minimal satu server!");
            return;
        }

        const domain = rawDomain + "." + rootDomain;

        if (rawDomain.endsWith(rootDomain)) {
          showWindowInfo("Hanya masukkan subdomain!");
          return;
        }
        
        if (!rawDomain.match(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)) {
            showWindowInfo("Format subdomain tidak valid!");
            return;
        }

        showWindowInfo("Membuat akun...");

        const serversArray = Array.from(selectedServers).join(',');
        const url = "https://" + rootDomain + "/api/v1/domains/put?domain=" + domain + "&name=" + encodeURIComponent(name) + "&servers=" + encodeURIComponent(serversArray);
        const res = fetch(url).then((res) => {
          if (res.status == 200) {
            showWindowInfo("Akun berhasil dibuat!");
            domainInputElement.value = "";
            nameInput.value = "";
            selectedServers.clear();
            updateSelectedServersDisplay();
            isDomainListFetched = false;
            getDomainList();
          } else {
            if (res.status == 409) {
              showWindowInfo("Akun sudah ada!");
            } else if (res.status == 403) {
              showWindowInfo("Subdomain mengandung kata terlarang!");
            } else {
              showWindowInfo("Error " + res.status);
            }
          }
        });
      }

      function copyToClipboard(text) {
        navigator.clipboard.writeText(text);
        showNotification();
      }
      
      function showWindowInfo(text) {
        windowInfoContainer.innerText = text;
        windowInfoContainer.removeAttribute('data-aos');
        void windowInfoContainer.offsetWidth;
        windowInfoContainer.setAttribute('data-aos', 'fade-in');
        AOS.refresh();
      }

      function showNotification() {
        notification.classList.remove("opacity-0");
        notification.classList.add("top-24");
        setTimeout(() => {
          notification.classList.add("opacity-0");
          notification.classList.remove("top-24");
        }, 3000);
      }

      function copyToClipboardAsRaw() {
        navigator.clipboard.writeText(rawConfig);
        showNotification();
        toggleOutputWindow();
      }

      async function copyToClipboardAsTarget(target) {
        showWindowInfo("Menghasilkan konfigurasi...");
        const url = converterUrl;
        const res = await fetch(url, {
          method: "POST",
          body: JSON.stringify({
            url: rawConfig,
            format: target,
            template: "cf",
          }),
        });

        if (res.status == 200) {
          showWindowInfo("Konfigurasi dihasilkan!");
          navigator.clipboard.writeText(await res.text());
          showNotification();
          toggleOutputWindow();
        } else {
          showWindowInfo("Error " + res.statusText);
        }
      }

      function navigateTo(link) {
        window.location.href = link + window.location.search;
      }

      function toggleOutputWindow() {
        showWindowInfo("Pilih Format Output:");
        toggleWindow();
        const rootElement = document.getElementById("output-window");
        rootElement.classList.toggle("hidden");
      }

      function toggleWildcardsWindow() {
        showWindowInfo("Buat Akun Baru");
        toggleWindow();
        if (!windowContainer.classList.contains("hidden")) {
            getDomainList();
        }
        const rootElement = document.getElementById("wildcards-window");
        rootElement.classList.toggle("hidden");
      }

      function toggleWindow() {
        const rootElement = document.getElementById("container-window");
        if (rootElement.classList.contains("hidden")) {
            rootElement.classList.remove("hidden");
            AOS.refresh();
        } else {
            rootElement.classList.add("hidden");
            document.getElementById("output-window").classList.add("hidden");
            document.getElementById("wildcards-window").classList.add("hidden");
        }
      }
      
      function setDarkModeIcon() {
        const rootElement = document.getElementById("html");
        const icon = document.getElementById("dark-mode-icon");
        if (rootElement.classList.contains("dark")) {
          icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />';
        } else {
          icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />';
        }
      }

      function toggleDarkMode() {
        const rootElement = document.getElementById("html");
        rootElement.classList.toggle("dark");
        setDarkModeIcon();
      }

      function checkProxy() {
        for (let i = 0; ; i++) {
          const pingElement = document.getElementById("ping-"+i);
          if (pingElement == undefined) return;

          const target = pingElement.dataset.target;
          if (target) {
            pingElement.textContent = "Memeriksa...";
            pingElement.classList.add("animate-pulse");
          } else {
            continue;
          }

          let isActive = false;
          new Promise(async (resolve) => {
            const res = await fetch("https://" + rootDomain + "/check?target=" + target)
              .then(async (res) => {
                if (isActive) return;
                pingElement.classList.remove("animate-pulse");
                if (res.status == 200) {
                  const jsonResp = await res.json();
                  if (jsonResp.proxyip === true) {
                    isActive = true;
                    pingElement.textContent = "Aktif | " + jsonResp.delay + " ms";
                    pingElement.classList.add("text-green-500");
                    // Store speed for sorting
                    const proxyCard = pingElement.closest('[data-proxy]');
                    if (proxyCard) {
                      proxyCard.setAttribute('data-speed', jsonResp.delay);
                    }
                  } else {
                    pingElement.textContent = "Tidak Aktif";
                    pingElement.classList.add("text-red-500");
                  }
                } else {
                  pingElement.textContent = "Gagal Memeriksa!";
                  pingElement.classList.add("text-red-500");
                }
              })
              .finally(() => {
                resolve(0);
              });
          });
        }
      }

      function checkGeoip() {
        const containerIP = document.getElementById("container-info-ip");
        const containerCountry = document.getElementById("container-info-country");
        const res = fetch("https://" + rootDomain + "/api/v1/myip").then(async (res) => {
          if (res.status == 200) {
            const respJson = await res.json();
            containerIP.querySelector('span').textContent = "IP: " + respJson.ip;
            containerCountry.querySelector('span').textContent = "Negara: " + respJson.country;
          }
        });
      }
    </script>
  </body>
</html>
`;

class Document {
  proxies = [];

  constructor(request) {
    this.html = baseHTML;
    this.request = request;
    this.url = new URL(this.request.url);
  }

  setTitle(title) {
    this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title);
  }

  addInfo(text) {
    text = `<span class="bg-gray-200 dark:bg-gray-700 px-3 py-1 rounded-full text-sm">${text}</span>`;
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `${text}\nPLACEHOLDER_INFO`);
  }

  registerProxies(data, proxies) {
    this.proxies.push({
      ...data,
      list: proxies,
    });
  }

  buildProxyGroup() {
    let proxyGroupElement = "";
    
    if (this.proxies.length === 0) {
        proxyGroupElement = `
        <div class="col-span-full text-center py-10" data-aos="fade-up">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mx-auto text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h3 class="mt-4 text-xl font-semibold text-gray-600 dark:text-gray-400">Server Tidak Ditemukan</h3>
            <p class="mt-2 text-gray-500 dark:text-gray-500">Coba ubah halaman atau filter negara.</p>
        </div>
        `;
    } else {
        for (let i = 0; i < this.proxies.length; i++) {
          const proxyData = this.proxies[i];
          const proxyIndex = proxyData.index;

          proxyGroupElement += `
          <div data-aos="fade-up" data-aos-delay="${(i % 4) * 100}" class="lozad server-card bg-white dark:bg-gray-800 rounded-xl shadow-md hover:shadow-xl transition-all duration-300 overflow-hidden group" id="server-card-${proxyIndex}" data-proxy data-country="${proxyData.country}" data-name="${proxyData.org}" data-ip="${proxyData.proxyIP}">
            <div class="p-4 border-b border-gray-100 dark:border-gray-700">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                  <input type="checkbox" id="server-checkbox-${proxyIndex}" class="custom-checkbox" onchange="toggleServerSelection('${proxyIndex}')">
                  <img width="32" class="rounded-full ring-2 ring-indonesia-red ring-offset-2 group-hover:scale-110 transition-transform" src="https://hatscripts.github.io/circle-flags/flags/${proxyData.country.toLowerCase()}.svg" />
                  <div>
                    <h5 class="font-semibold text-gray-800 dark:text-white truncate">${proxyData.org}</h5>
                    <p class="text-xs text-gray-500 dark:text-gray-400">${proxyData.country}</p>
                  </div>
                </div>
                <div id="ping-${proxyIndex}" data-target="${proxyData.proxyIP}:${proxyData.proxyPort}" class="text-xs font-semibold text-gray-500 dark:text-gray-400">Diam</div>
              </div>
            </div>

            <div class="p-4">
              <div class="text-sm text-gray-600 dark:text-gray-400 mb-4">
                <p><span class="font-medium text-gray-800 dark:text-gray-200">IP:</span> ${proxyData.proxyIP}</p>
                <p><span class="font-medium text-gray-800 dark:text-gray-200">Port:</span> ${proxyData.proxyPort}</p>
                <div id="container-region-check-${proxyIndex}">
                  <input id="config-sample-${proxyIndex}" class="hidden" type="text" value="${proxyData.list[0]}">
                </div>
              </div>

              <div class="grid grid-cols-3 gap-2 text-sm">
                ${this.buildProxyButtons(proxyData.list, proxyIndex)}
              </div>
            </div>
          </div>
          `;
        }
    }

    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", proxyGroupElement);
  }

  buildProxyButtons(proxyList, proxyIndex) {
    const indexName = [
      `${reverse("NAJORT")} TLS`,
      `${reverse("SSELV")} TLS`,
      `${reverse("SS")} TLS`,
      `${reverse("NAJORT")} NTLS`,
      `${reverse("SSELV")} NTLS`,
      `${reverse("SS")} NTLS`,
    ];
    
    let buttonsHTML = "";
    for (let x = 0; x < proxyList.length; x++) {
      const proxy = proxyList[x];
      buttonsHTML += `<button class="bg-gradient-to-r from-indonesia-red to-red-600 text-white text-xs font-medium rounded-md p-2 w-full transition-all duration-200 hover:from-red-600 hover:to-red-700 hover:scale-105 hover:shadow-lg" onclick="copyToClipboard('${proxy}')">${indexName[x]}</button>`;
    }
    return buttonsHTML;
  }

  buildCountryFlag() {
    const proxyBankUrl = this.url.searchParams.get("proxy-list");
    const flagList = [];
    for (const proxy of cachedProxyList) {
      flagList.push(proxy.country);
    }

    let flagElement = "";
    for (const flag of new Set(flagList)) {
      const queryParams = new URLSearchParams(this.url.searchParams);
      queryParams.set("cc", flag);
      if (proxyBankUrl) {
        queryParams.set("proxy-list", proxyBankUrl);
      }
      
      flagElement += `
      <button onclick="toggleCountryFilter('${flag}')" class="country-filter px-3 py-1 rounded-full text-sm font-medium bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 hover:bg-indonesia-red hover:text-white transition-colors" data-country="${flag}">
        <img width="16" class="inline mr-1" src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" />
        ${flag}
      </button>
      `;
    }

    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }

  addPageButton(text, link, isDisabled) {
    const pageButton = `
    <li>
      <button ${isDisabled ? "disabled" : ""} 
              class="px-4 py-2 font-medium bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 border border-gray-300 dark:border-gray-600 rounded-lg shadow-sm transition-all hover:bg-indonesia-red hover:text-white hover:border-indonesia-red disabled:opacity-50 disabled:cursor-not-allowed" 
              onclick=navigateTo('${link}')>
        ${text}
      </button>
    </li>`;

    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
  }

  build() {
    this.buildProxyGroup();
    this.buildCountryFlag();

    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");

    return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
  }
}