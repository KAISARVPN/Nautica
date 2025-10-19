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
    document.setTitle("Welcome to <span class='text-blue-500 font-semibold'>KaisarStore</span>");
    document.addInfo(`Total Servers: ${proxyList.length}`);
    document.addInfo(`Page: ${page + 1}/${Math.ceil(proxyList.length / PROXY_PER_PAGE)}`);

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
    document.addPageButton("Prev", `/sub/${page > 0 ? page - 1 : 0}`, page <= 0);
    document.addPageButton("Next", `/sub/${page + 1}`, (startIndex + PROXY_PER_PAGE) >= proxyList.length);

    return document.build();
  } catch (error) {
    return `An error occurred while generating the ${reverse("SSELV")} configurations. ${error}`;
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
            const register = await cloudflareApi.registerDomain(domain);

            return new Response(register.toString(), {
              status: register,
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
      return new Response(`An error occurred: ${err.toString()}`, {
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

function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

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

  async registerDomain(domain) {
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
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
}

// ==================================================================================
// =================== PERUBAHAN TAMPILAN WEB DIMULAI DARI SINI ===================
// ==================================================================================

// HTML page base
/**
 * Tampilan web diubah total menjadi lebih modern, elegan, dan beranimasi.
 * Menggunakan AOS (Animate On Scroll) untuk animasi.
 * Layout diubah menjadi sidebar (kategori) + content (produk).
 */
let baseHTML = `
<!DOCTYPE html>
<html lang="en" id="html" class="scroll-smooth dark">
  <head>
    <meta charset="UTF-g" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Proxy Store</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    
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
        font-family: 'Inter', sans-serif;
      }

      /* Custom style for AOS */
      [data-aos] {
        transition-property: transform, opacity;
      }
    </style>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/lozad/dist/lozad.min.js"></script>
    <script>
      tailwind.config = {
        darkMode: 'selector',
        theme: {
          extend: {
            fontFamily: {
              sans: ['Inter', 'sans-serif'],
            },
          },
        },
      }
    </script>
  </head>
  <body class="bg-gray-100 dark:bg-neutral-900 text-neutral-800 dark:text-neutral-200 selection:bg-blue-500 selection:text-white">

    <aside data-aos="fade-right" class="fixed top-0 left-0 z-40 w-20 h-screen bg-white dark:bg-neutral-800 shadow-lg transition-all duration-300">
      <div class="flex flex-col items-center h-full py-4 space-y-4 overflow-y-auto scrollbar-hide">
        <a href="/sub" class="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-neutral-700" title="Home">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-7 text-blue-500">
            <path d="M11.47 3.841a.75.75 0 0 1 1.06 0l8.69 8.69a.75.75 0 1 0 1.06-1.061l-8.689-8.69a2.25 2.25 0 0 0-3.182 0l-8.69 8.69a.75.75 0 1 0 1.061 1.06l8.69-8.689Z" />
            <path d="m12 5.432 8.159 8.159c.03.03.06.058.091.086v6.198c0 1.035-.84 1.875-1.875 1.875H15a.75.75 0 0 1-.75-.75v-4.5a.75.75 0 0 0-.75-.75h-3a.75.75 0 0 0-.75.75V21a.75.75 0 0 1-.75.75H5.625a1.875 1.875 0 0 1-1.875-1.875v-6.198a2.29 2.29 0 0 0 .091-.086L12 5.432Z" />
          </svg>
        </a>
        <hr class="w-3/4 border-gray-200 dark:border-neutral-700">
        <div id="country-flag-container" class="flex flex-col items-center h-full gap-3">
          PLACEHOLDER_BENDERA_NEGARA
        </div>
      </div>
    </aside>

    <main class="ml-20 transition-all duration-300">
      
      <header data-aos="fade-down" class="sticky top-0 z-30 bg-white/80 dark:bg-neutral-800/80 backdrop-blur-md shadow-sm">
        <div class="container mx-auto px-6 py-4">
          <div class="flex items-center justify-between">
            <h1 id="container-title" class="text-2xl font-bold text-neutral-800 dark:text-white">
              PLACEHOLDER_JUDUL
            </h1>
            
            <div class="flex items-center gap-6">
              <div id="container-info" class="flex items-center gap-4 text-xs text-neutral-500 dark:text-neutral-400">
                <p id="container-info-ip">IP: ...</p>
                <p id="container-info-country" class="hidden md:block">Country: ...</p>
                <p id="container-info-isp" class="hidden lg:block">ISP: ...</p>
              </div>
              <button onclick="toggleDarkMode()" class="bg-gray-200 dark:bg-neutral-700 rounded-full p-2 transition-all hover:bg-gray-300 dark:hover:bg-neutral-600" title="Toggle Dark Mode">
                <svg id="dark-mode-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </header>

      <section class="container mx-auto px-6 py-8" data-aos="fade-up" data-aos-delay="100">
        <div class="p-8 bg-white dark:bg-neutral-800 rounded-lg shadow-md">
          <h2 class="text-3xl font-bold mb-3">Jelajahi Server Premium Kami</h2>
          <p class="text-neutral-600 dark:text-neutral-300 mb-2">Pilih server dari berbagai lokasi di seluruh dunia. Cepat, aman, dan andal.</p>
          <div class="flex gap-4 text-sm font-medium text-neutral-700 dark:text-neutral-200">
            PLACEHOLDER_INFO
          </div>
        </div>
      </section>

      <section class="container mx-auto px-6 py-6">
        <div id="proxy-grid-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          PLACEHOLDER_PROXY_GROUP
        </div>
      </section>

      <nav id="container-pagination" class="container mx-auto px-6 py-10" data-aos="fade-up">
        <ul class="flex justify-center items-center gap-4">
          PLACEHOLDER_PAGE_BUTTON
        </ul>
      </nav>

      <footer class="container mx-auto px-6 py-6 text-center text-sm text-neutral-500">
        <p>&copy; 2025 ${serviceName}.${rootDomain}. All rights reserved.</p>
      </footer>
    </main>

    <footer class="fixed bottom-6 right-6 z-40 flex flex-col gap-3">
      <a href="${DONATE_LINK}" target="_blank" title="Donasi">
        <button class="bg-green-500 text-white rounded-full p-3 shadow-lg transition-all hover:bg-green-600 hover:scale-110">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
            <path d="M10.464 8.746c.227-.18.497-.311.786-.394v2.795a2.252 2.252 0 0 1-.786-.393c-.394-.313-.546-.681-.546-1.004 0-.323.152-.691.546-1.004ZM12.75 15.662v-2.824c.347.085.664.228.921.421.427.32.579.686.579.991 0 .305-.152.671-.579.991a2.534 2.534 0 0 1-.921.42Z" />
            <path fill-rule="evenodd" d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25ZM12.75 6a.75.75 0 0 0-1.5 0v.816a3.836 3.836 0 0 0-1.72.756c-.712.566-1.112 1.35-1.112 2.178 0 .829.4 1.612 1.113 2.178.502.4 1.102.647 1.719.756v2.978a2.536 2.536 0 0 1-.921-.421l-.879-.66a.75.75 0 0 0-.9 1.2l.879.66c.533.4 1.169.645 1.821.75V18a.75.75 0 0 0 1.5 0v-.81a4.124 4.124 0 0 0 1.821-.749c.745-.559 1.179-1.344 1.179-2.191 0-.847-.434-1.632-1.179-2.191a4.122 4.122 0 0 0-1.821-.75V8.354c.29.082.559.213.786.393l.415.33a.75.75 0 0 0 .933-1.175l-.415-.33a3.836 3.836 0 0 0-1.719-.755V6Z" clip-rule="evenodd" />
          </svg>
        </button>
      </a>
      <button onclick="toggleWildcardsWindow()" title="Wildcard Domains" class="bg-indigo-500 text-white rounded-full p-3 shadow-lg transition-all hover:bg-indigo-600 hover:scale-110 PLACEHOLDER_API_READY">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-6">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 9V4.5M9 9H4.5M9 9 3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5 5.25 5.25" />
        </svg>
      </button>
    </footer>

    <div
      id="notification-badge"
      class="fixed z-50 opacity-0 transition-all ease-in-out duration-300 top-24 right-6 p-4 max-w-sm bg-white dark:bg-neutral-800 rounded-xl shadow-lg border border-gray-200 dark:border-neutral-700 flex items-center gap-x-4"
    >
      <div class="shrink-0">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6 text-green-500">
          <path fill-rule="evenodd" d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12Zm13.36-1.814a.75.75 0 1 0-1.06-1.06l-3.002 3.001-1.502-1.502a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.06 0l3.75-3.75Z" clip-rule="evenodd" />
        </svg>
      </div>
      <div>
        <div class="text-md font-bold text-blue-500">Berhasil!</div>
        <p class="text-sm text-neutral-800 dark:text-neutral-200">Konfigurasi berhasil disalin!</p>
      </div>
    </div>

    <div id="container-window" class="hidden fixed inset-0 z-40 bg-black/60 backdrop-blur-sm">
      <div data-aos="zoom-in" data-aos-duration="300" class="fixed z-50 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg p-6">
        <p id="container-window-info" class="text-center w-full text-lg font-medium text-white"></p>
        
        <div id="output-window" class="w-full h-full flex flex-col gap-4 text-center rounded-md hidden">
          <div class="grid grid-cols-3 gap-3">
              <button onclick="copyToClipboardAsTarget('clash')" class="p-3 rounded-lg bg-blue-500 text-white font-semibold transition-all hover:bg-blue-600 hover:scale-105">
                Clash
              </button>
              <button onclick="copyToClipboardAsTarget('sfa')" class="p-3 rounded-lg bg-blue-500 text-white font-semibold transition-all hover:bg-blue-600 hover:scale-105">
                SFA
              </button>
              <button onclick="copyToClipboardAsTarget('bfr')" class="p-3 rounded-lg bg-blue-500 text-white font-semibold transition-all hover:bg-blue-600 hover:scale-105">
                BFR
              </button>
          </div>
          <div class="grid grid-cols-2 gap-3">
              <button onclick="copyToClipboardAsTarget('v2ray')" class="p-3 rounded-lg bg-white dark:bg-neutral-700 text-neutral-800 dark:text-white font-semibold transition-all hover:bg-gray-100 dark:hover:bg-neutral-600 hover:scale-105">
                V2Ray/Xray
              </button>
              <button onclick="copyToClipboardAsRaw()" class="p-3 rounded-lg bg-white dark:bg-neutral-700 text-neutral-800 dark:text-white font-semibold transition-all hover:bg-gray-100 dark:hover:bg-neutral-600 hover:scale-105">
                Raw
              </button>
          </div>
          <div class="mt-4">
              <button onclick="toggleOutputWindow()" class="w-1/2 p-3 border-2 border-red-400 text-red-400 font-semibold rounded-lg transition-all hover:bg-red-400 hover:text-white">
                Close
              </button>
          </div>
        </div>
        
        <div id="wildcards-window" class="w-full h-full flex flex-col gap-4 rounded-md hidden">
          <div class="flex w-full h-full gap-2 justify-between">
              <input
                id="new-domain-input"
                type="text"
                placeholder="Input subdomain (cth: mydomain)"
                class="flex-grow w-full h-full px-4 py-3 rounded-lg focus:outline-0 focus:ring-2 focus:ring-blue-500 border-none"
              />
              <button
                onclick="registerDomain()"
                class="p-3 rounded-lg bg-blue-500 text-white transition-all hover:bg-blue-600"
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                  <path fill-rule="evenodd" d="M16.72 7.72a.75.75 0 0 1 1.06 0l3.75 3.75a.75.75 0 0 1 0 1.06l-3.75 3.75a.75.75 0 1 1-1.06-1.06l2.47-2.47H3a.75.75 0 0 1 0-1.5h16.19l-2.47-2.47a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd"/>
                </svg>
              </button>
          </div>
          <div class="basis-5/6 w-full h-80 rounded-md bg-white dark:bg-neutral-800 p-4">
            <div
              id="container-domains"
              class="w-full h-full rounded-md flex flex-col gap-2 overflow-y-scroll scrollbar-hide text-neutral-800 dark:text-white"
            >
              </div>
          </div>
          <button
                onclick="toggleWildcardsWindow()"
                class="w-full border-2 border-red-400 text-red-400 hover:bg-red-400 dark:text-white p-3 rounded-lg flex justify-center items-center transition-all"
              >
                Close
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
      const converterUrl =
        "https://script.google.com/macros/s/AKfycbwwVeHNUlnP92syOP82p1dOk_-xwBgRIxkTjLhxxZ5UXicrGOEVNc5JaSOu0Bgsx_gG/exec";


      // Switches
      let isDomainListFetched = false;

      // Local variable
      let rawConfig = "";

      function getDomainList() {
        if (isDomainListFetched) return;
        isDomainListFetched = true;

        windowInfoContainer.innerText = "Fetching data...";
        const domainListContainer = document.getElementById("container-domains");
        domainListContainer.innerHTML = '<p class="text-center">Loading...</p>';

        const url = "https://" + rootDomain + "/api/v1/domains/get";
        const res = fetch(url).then(async (res) => {
          domainListContainer.innerHTML = "";

          if (res.status == 200) {
            windowInfoContainer.innerText = "Registered Domains";
            const respJson = await res.json();
            if (respJson.length === 0) {
              domainListContainer.innerHTML = '<p class="text-center text-neutral-500">No domains registered.</p>';
              return;
            }
            for (const domain of respJson) {
              const domainElement = document.createElement("p");
              domainElement.classList.add("w-full", "bg-gray-100", "dark:bg-neutral-700", "p-3", "rounded-md", "font-medium");
              domainElement.innerText = domain;
              domainListContainer.appendChild(domainElement);
            }
          } else {
            windowInfoContainer.innerText = "Failed!";
            domainListContainer.innerHTML = '<p class="text-center text-red-500">Failed to fetch list.</p>';
          }
        });
      }

      function registerDomain() {
        const domainInputElement = document.getElementById("new-domain-input");
        const rawDomain = domainInputElement.value.toLowerCase().trim();
        
        if (!rawDomain) {
            showWindowInfo("Domain input cannot be empty!");
            return;
        }

        const domain = rawDomain + "." + rootDomain;

        if (rawDomain.endsWith(rootDomain)) {
          showWindowInfo("Please only input the subdomain.");
          return;
        }
        
        if (!rawDomain.match(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)) {
            showWindowInfo("Invalid subdomain format!");
            return;
        }


        showWindowInfo("Pushing request...");

        const url = "https://" + rootDomain + "/api/v1/domains/put?domain=" + domain;
        const res = fetch(url).then((res) => {
          if (res.status == 200) {
            showWindowInfo("Done!");
            domainInputElement.value = "";
            isDomainListFetched = false;
            getDomainList();
          } else {
            if (res.status == 409) {
              showWindowInfo("Domain already exists!");
            } else if (res.status == 403) {
              showWindowInfo("Domain contains bad words!");
            } else {
              showWindowInfo("Error " + res.status);
            }
          }
        });
      }

      function copyToClipboard(text) {
        toggleOutputWindow();
        rawConfig = text;
      }
      
      function showWindowInfo(text) {
        windowInfoContainer.innerText = text;
        // Re-trigger AOS animation for the info text if needed
        windowInfoContainer.removeAttribute('data-aos');
        void windowInfoContainer.offsetWidth; // Trigger reflow
        windowInfoContainer.setAttribute('data-aos', 'fade-in');
        AOS.refresh();
      }

      function showNotification() {
        notification.classList.remove("opacity-0");
        notification.classList.add("top-24"); // Muncul
        setTimeout(() => {
          notification.classList.add("opacity-0");
          notification.classList.remove("top-24");
        }, 2000);
      }

      function copyToClipboardAsRaw() {
        navigator.clipboard.writeText(rawConfig);
        showNotification();
        toggleOutputWindow(); // Tutup modal setelah copy
      }

      async function copyToClipboardAsTarget(target) {
        showWindowInfo("Generating config...");
        const url = "${CONVERTER_URL}";
        const res = await fetch(url, {
          method: "POST",
          body: JSON.stringify({
            url: rawConfig,
            format: target,
            template: "cf",
          }),
        });

        if (res.status == 200) {
          showWindowInfo("Done!");
          navigator.clipboard.writeText(await res.text());
          showNotification();
          toggleOutputWindow(); // Tutup modal setelah copy
        } else {
          showWindowInfo("Error " + res.statusText);
        }
      }

      function navigateTo(link) {
        window.location.href = link + window.location.search;
      }

      function toggleOutputWindow() {
        showWindowInfo("Select Output Format:");
        toggleWindow();
        const rootElement = document.getElementById("output-window");
        rootElement.classList.toggle("hidden");
      }

      function toggleWildcardsWindow() {
        showWindowInfo("Domain list");
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
            // Re-initialize AOS for modals
            AOS.refresh();
        } else {
            rootElement.classList.add("hidden");
            // Sembunyikan semua window spesifik saat modal ditutup
            document.getElementById("output-window").classList.add("hidden");
            document.getElementById("wildcards-window").classList.add("hidden");
        }
      }

      function toggleDarkMode() {
        const rootElement = document.getElementById("html");
        rootElement.classList.toggle("dark");
        
        // Ganti ikon berdasarkan state
        const icon = document.getElementById("dark-mode-icon");
        if (rootElement.classList.contains("dark")) {
          icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />';
        } else {
          icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />';
        }
      }

      function checkProxy() {
        for (let i = 0; ; i++) {
          const pingElement = document.getElementById("ping-"+i);
          if (pingElement == undefined) return;

          const target = pingElement.dataset.target;
          if (target) {
            pingElement.textContent = "Checking...";
            pingElement.classList.add("animate-pulse");
          } else {
            continue;
          }

          let isActive = false;
          new Promise(async (resolve) => {
            const res = await fetch("https://${serviceName}.${rootDomain}/check?target=" + target)
              .then(async (res) => {
                if (isActive) return;
                pingElement.classList.remove("animate-pulse");
                if (res.status == 200) {
                  const jsonResp = await res.json();
                  if (jsonResp.proxyip === true) {
                    isActive = true;
                    pingElement.textContent = "Active | " + jsonResp.delay + " ms (" + jsonResp.colo + ")";
                    pingElement.classList.add("text-green-500");
                  } else {
                    pingElement.textContent = "Inactive";
                    pingElement.classList.add("text-red-500");
                  }
                } else {
                  pingElement.textContent = "Check Failed!";
                  pingElement.classList.add("text-red-500");
                }
              })
              .finally(() => {
                resolve(0);
              });
          });
        }
      }

      function checkRegion() {
        // Fungsi ini tampaknya tidak digunakan di HTML asli, jadi saya biarkan
        for (let i = 0; ; i++) {
          console.log("Halo " + i)
          const containerRegionCheck = document.getElementById("container-region-check-" + i);
          const configSample = document.getElementById("config-sample-" + i)?.value.replaceAll(" ", "");
          if (containerRegionCheck == undefined || !configSample) break;

          const res = fetch(
            "https://api.foolvpn.me/regioncheck?config=" + encodeURIComponent(configSample)
          ).then(async (res) => {
            if (res.status == 200) {
              containerRegionCheck.innerHTML = "<hr class='my-1 border-neutral-300 dark:border-neutral-600'>";
              for (const result of await res.json()) {
                containerRegionCheck.innerHTML += "<p class='text-xs'>" + result.name + ": " + result.region + "</p>";
              }
            }
          });
        }
      }

      function checkGeoip() {
        const containerIP = document.getElementById("container-info-ip");
        const containerCountry = document.getElementById("container-info-country");
        const containerISP = document.getElementById("container-info-isp");
        const res = fetch("https://" + rootDomain + "/api/v1/myip").then(async (res) => {
          if (res.status == 200) {
            const respJson = await res.json();
            containerIP.innerText = "IP: " + respJson.ip;
            containerCountry.innerText = "Country: " + respJson.country;
            containerISP.innerText = "ISP: " + respJson.asOrganization;
          }
        });
      }

      window.onload = () => {
        // Panggil AOS.init() untuk mengaktifkan animasi
        AOS.init({
          duration: 600,
          easing: 'ease-in-out-cubic',
          once: true,
        });

        checkGeoip();
        checkProxy();
        // checkRegion(); // Uncomment jika Anda ingin menggunakannya
        toggleDarkMode(); // Set ikon dark mode dengan benar saat load
        toggleDarkMode(); 

        const observer = lozad(".lozad", {
          load: function (el) {
            el.classList.remove("scale-95"); // Hapus scale-95 jika ada
          },
        });
        observer.observe();
      };
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
    text = `<span class="bg-gray-200 dark:bg-neutral-700 px-3 py-1 rounded-full">${text}</span>`;
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
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="size-16 mx-auto text-neutral-400">
              <path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
            </svg>
            <h3 class="mt-4 text-2xl font-semibold text-neutral-700 dark:text-neutral-300">Tidak Ada Server Ditemukan</h3>
            <p class="mt-2 text-neutral-500">Coba ganti halaman atau filter negara Anda.</p>
        </div>
        `;
    } else {
        for (let i = 0; i < this.proxies.length; i++) {
          const proxyData = this.proxies[i];
          const proxyIndex = proxyData.index; // Ambil index asli

          // Ini adalah "Product Card" yang baru
          proxyGroupElement += `
          <div data-aos="fade-up" data-aos-delay="${(i % 4) * 100}" class="lozad bg-white dark:bg-neutral-800 rounded-lg shadow-lg overflow-hidden transition-all duration-300 hover:shadow-2xl hover:-translate-y-1">
            <div class="p-4 bg-gray-50 dark:bg-neutral-700/50 border-b border-gray-200 dark:border-neutral-700">
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                  <img width="32" class="rounded-full shadow-md" src="https://hatscripts.github.io/circle-flags/flags/${proxyData.country.toLowerCase()}.svg" />
                  <h5 class="font-bold text-lg text-neutral-800 dark:text-white truncate">${proxyData.org}</h5>
                </div>
                <div id="ping-${proxyIndex}" data-target="${proxyData.proxyIP}:${proxyData.proxyPort}" class="text-xs font-semibold text-neutral-500 dark:text-neutral-400">Idle</div>
              </div>
            </div>

            <div class="p-4">
              <div class="text-sm text-neutral-600 dark:text-neutral-300 mb-4">
                <p><span class="font-medium text-neutral-800 dark:text-neutral-100">IP:</span> ${proxyData.proxyIP}</p>
                <p><span class="font-medium text-neutral-800 dark:text-neutral-100">Port:</span> ${proxyData.proxyPort}</p>
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
      // Tombol baru yang lebih elegan
      buttonsHTML += `<button class="bg-blue-500 text-white text-xs font-semibold rounded-md p-2 w-full transition-all duration-200 ease-in-out transform hover:bg-blue-600 hover:scale-105" onclick="copyToClipboard('${proxy}')">${indexName[x]}</button>`;
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
      <a href="/sub?${queryParams.toString()}" class="p-2 rounded-lg transition-all hover:bg-gray-200 dark:hover:bg-neutral-700" title="${flag}">
        <img width=28 src="https://hatscripts.github.io/circle-flags/flags/${flag.toLowerCase()}.svg" />
      </a>
      `;
    }

    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }

  addPageButton(text, link, isDisabled) {
    const pageButton = `
    <li>
      <button ${isDisabled ? "disabled" : ""} 
              class="px-5 py-2 font-semibold bg-white dark:bg-neutral-800 border border-gray-300 dark:border-neutral-700 rounded-lg shadow-sm transition-all hover:bg-gray-100 dark:hover:bg-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed" 
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
