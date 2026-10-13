"use strict";

/*
 * Login Recorder for Burp Suite - Firefox background script (MV3 event page).
 *
 * Port of the Chrome service worker (background/recorder-service-worker.js).
 * The recording state machine and the emitted JSON event schema are kept
 * identical to the original so that Burp can consume the output unchanged.
 *
 * Firefox-specific differences:
 *   - Event page (background.scripts) instead of a service worker.
 *   - Native `browser.*` promise API.
 *   - Clipboard is written directly from the background document
 *     (no chrome.offscreen document needed / available).
 *   - browser.privacy.services only exposes passwordSavingEnabled; the
 *     autofill* settings are used when present and skipped otherwise.
 *   - Privacy settings are handed back with clear() instead of re-setting a
 *     remembered value, so a suspended/restarted event page cannot "restore"
 *     an already-disabled value.
 */

// ---------------------------------------------------------------------------
// Storage keys (shared with popup/js/popup.js)
// ---------------------------------------------------------------------------
const RECORDING = "recording";
const LAST_RECORDING = "lastRecording";
const WEBAUTHN_ENABLED = "webauthnEnabled";
const WEBAUTHN_CREDENTIALS = "webauthnCredentials";
const POPUP_WINDOW_ID = "popupWindowId";
const BYPASS_INCOGNITO = "bypassIncognito"; // storage.sync

const EXTENSION_NAME = "Login Recorder for Burp Suite";
const imageUrl = (name) => browser.runtime.getURL(`images/${name}`);

const log = (...args) => console.log(...args);

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return;
    } catch (err) {
        log("navigator.clipboard.writeText failed, falling back to execCommand", err);
    }
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand("copy");
    } finally {
        textarea.remove();
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers (base64 / CBOR) used by the software WebAuthn authenticator
// ---------------------------------------------------------------------------
// Fixed AAGUID advertised in attested credential data (copied from the original).
const AAGUID = new Uint8Array([201, 202, 223, 201, 137, 169, 72, 158, 162, 90, 199, 232, 106, 77, 95, 21]);

function toBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function fromBase64(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function toBase64Url(buffer) {
    return toBase64(buffer).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatBytes(...arrays) {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}

function cborHead(majorType, value) {
    const major = majorType << 5;
    if (value < 24) return new Uint8Array([major | value]);
    if (value < 256) return new Uint8Array([24 | major, value]);
    if (value < 65536) return new Uint8Array([25 | major, value >> 8, value & 255]);
    return new Uint8Array([
        26 | major,
        (value >> 24) & 255,
        (value >> 16) & 255,
        (value >> 8) & 255,
        value & 255,
    ]);
}
const cborUint = (n) => cborHead(0, n);
const cborNegInt = (n) => cborHead(1, -1 - n);
const cborBytes = (bytes) => concatBytes(cborHead(2, bytes.length), bytes);
const cborText = (text) => {
    const bytes = new TextEncoder().encode(text);
    return concatBytes(cborHead(3, bytes.length), bytes);
};

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Convert a WebCrypto (IEEE P1363, r||s) ECDSA signature to ASN.1 DER. */
function rawSignatureToDer(signature) {
    const encodeInteger = (raw) => {
        let start = 0;
        while (start < raw.length - 1 && raw[start] === 0) start++;
        const value = raw.slice(start);
        const needsPad = value[0] & 128;
        const length = value.length + (needsPad ? 1 : 0);
        const out = new Uint8Array(2 + length);
        out[0] = 2;
        out[1] = length;
        if (needsPad) {
            out[2] = 0;
            out.set(value, 3);
        } else {
            out.set(value, 2);
        }
        return out;
    };
    const r = encodeInteger(signature.slice(0, 32));
    const s = encodeInteger(signature.slice(32, 64));
    const body = r.length + s.length;
    const out = new Uint8Array(2 + body);
    out[0] = 48;
    out[1] = body;
    out.set(r, 2);
    out.set(s, 2 + r.length);
    return out;
}

/** Resolve and validate the RP ID against the requesting origin. */
function resolveRpId(rpId, origin) {
    const hostname = new URL(origin).hostname.toLowerCase();
    const id = (rpId ?? hostname).toLowerCase();
    if (id !== hostname && !hostname.endsWith("." + id)) {
        throw new DOMException(`Invalid rp.id "${id}" for origin "${origin}"`, "SecurityError");
    }
    return id;
}

/** Bridge messages may carry plain arrays / ArrayBuffers; normalise to Uint8Array. */
function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer || Array.isArray(value)) return new Uint8Array(value);
    return value;
}

function normalizeRequest(request) {
    const options = request.options;
    if (options.challenge) options.challenge = toBytes(options.challenge);
    if (options.user?.id) options.user.id = toBytes(options.user.id);
    if (options.excludeCredentials) {
        for (const c of options.excludeCredentials) if (c.id) c.id = toBytes(c.id);
    }
    if (options.allowCredentials) {
        for (const c of options.allowCredentials) if (c.id) c.id = toBytes(c.id);
    }
    for (const param of options.pubKeyCredParams ?? []) {
        if (typeof param.alg === "string") param.alg = Number(param.alg);
    }
    return request;
}

// ---------------------------------------------------------------------------
// Passkey credential store (storage.session)
// ---------------------------------------------------------------------------
const credentialStore = {
    async isEnabled() {
        return (await browser.storage.session.get(WEBAUTHN_ENABLED))[WEBAUTHN_ENABLED] ?? false;
    },
    async getCredentials() {
        return (await browser.storage.session.get(WEBAUTHN_CREDENTIALS))[WEBAUTHN_CREDENTIALS] ?? [];
    },
    async addCredential(credential) {
        const credentials = await this.getCredentials();
        const index = credentials.findIndex((c) => c.credentialId === credential.credentialId);
        if (index >= 0) credentials[index] = credential;
        else credentials.push(credential);
        await browser.storage.session.set({ [WEBAUTHN_CREDENTIALS]: credentials });
    },
};

// ---------------------------------------------------------------------------
// Software WebAuthn authenticator (ES256 platform authenticator)
// ---------------------------------------------------------------------------
const authenticator = {
    async handleRequest(request) {
        if (request.type === "create") return this.create(request);
        if (request.type === "get") return this.get(request);
        throw new DOMException(`Unknown request type: ${request.type}`, "NotSupportedError");
    },

    async create(request) {
        const options = request.options;
        const rpId = resolveRpId(options.rp.id, request.origin);

        if (!options.pubKeyCredParams.some((p) => p.alg === -7)) {
            throw new DOMException("Only ES256 (alg: -7) is supported", "NotSupportedError");
        }

        const isResident =
            options.authenticatorSelection?.residentKey !== "discouraged" ||
            options.authenticatorSelection?.requireResidentKey === true;

        const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
            "sign",
            "verify",
        ]);
        const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
        const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
        const x = publicKeyRaw.slice(1, 33);
        const y = publicKeyRaw.slice(33, 65);
        const credentialId = crypto.getRandomValues(new Uint8Array(32));

        // COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        const coseKey = concatBytes(
            new Uint8Array([165]),
            cborUint(1), cborUint(2),
            cborUint(3), cborNegInt(-7),
            cborNegInt(-1), cborUint(1),
            cborNegInt(-2), cborBytes(x),
            cborNegInt(-3), cborBytes(y)
        );

        // authenticatorData: rpIdHash | flags(UP,UV,BE,BS,AT) | signCount | AAGUID | credIdLen | credId | coseKey
        const rpIdHash = await sha256(new TextEncoder().encode(rpId));
        const credIdLength = new Uint8Array([(credentialId.length >> 8) & 255, credentialId.length & 255]);
        const authenticatorData = concatBytes(
            rpIdHash,
            new Uint8Array([93]),
            new Uint8Array(4),
            AAGUID,
            credIdLength,
            credentialId,
            coseKey
        );

        // attestationObject {"fmt": "none", "attStmt": {}, "authData": bytes}
        const attestationObject = concatBytes(
            new Uint8Array([163]),
            cborText("fmt"), cborText("none"),
            cborText("attStmt"), new Uint8Array([160]),
            cborText("authData"), cborBytes(authenticatorData)
        );

        const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({
                type: "webauthn.create",
                challenge: toBase64Url(options.challenge),
                origin: request.origin,
                crossOrigin: request.crossOrigin,
            })
        );

        const stored = {
            credentialId: toBase64(credentialId),
            privateKey: toBase64(privateKeyPkcs8),
            relyingPartyId: rpId,
            isResidentCredential: isResident,
            userHandle: toBase64(options.user.id),
            userName: options.user.name,
            userDisplayName: options.user.displayName,
        };
        await credentialHooks.onStoreCredential(stored);

        return {
            type: "create",
            credential: {
                id: toBase64Url(credentialId),
                rawId: credentialId.slice(),
                type: "public-key",
                authenticatorAttachment: "platform",
                response: {
                    clientDataJSON,
                    attestationObject,
                    transports: ["internal"],
                    publicKey: publicKeyRaw,
                    publicKeyAlgorithm: -7,
                    authenticatorData,
                },
            },
        };
    },

    async get(request) {
        const options = request.options;
        const rpId = resolveRpId(options.rpId, request.origin);
        const credentials = await credentialStore.getCredentials();

        let credential;
        if (options.allowCredentials && options.allowCredentials.length > 0) {
            const allowed = new Set(options.allowCredentials.map((c) => toBase64(c.id)));
            credential = credentials.find((c) => c.relyingPartyId === rpId && allowed.has(c.credentialId));
        } else {
            credential = credentials.find((c) => c.relyingPartyId === rpId && c.isResidentCredential);
        }
        if (!credential) return { type: "get", declined: true };

        // authenticatorData: rpIdHash | flags(UP,UV,BE,BS) | signCount
        const rpIdHash = await sha256(new TextEncoder().encode(rpId));
        const authenticatorData = concatBytes(rpIdHash, new Uint8Array([29]), new Uint8Array(4));

        const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({
                type: "webauthn.get",
                challenge: toBase64Url(options.challenge),
                origin: request.origin,
                crossOrigin: request.crossOrigin,
            })
        );

        const signedData = concatBytes(authenticatorData, await sha256(clientDataJSON));
        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            fromBase64(credential.privateKey),
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign"]
        );
        const rawSignature = new Uint8Array(
            await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, signedData)
        );
        const signature = rawSignatureToDer(rawSignature);

        credentialHooks.onCredentialUsed(credential);

        const rawId = fromBase64(credential.credentialId);
        return {
            type: "get",
            credential: {
                id: toBase64Url(rawId),
                rawId,
                type: "public-key",
                authenticatorAttachment: "platform",
                response: {
                    clientDataJSON,
                    authenticatorData,
                    signature,
                    userHandle: credential.userHandle ? fromBase64(credential.userHandle) : null,
                },
            },
        };
    },
};

const credentialHooks = {
    async onStoreCredential(credential) {
        try {
            await credentialStore.addCredential(credential);
        } catch (err) {
            console.error("Failed to store WebAuthn credential", err);
        }
        recorder.addWebAuthnCredential(credential);
    },
    onCredentialUsed(credential) {
        recorder.addWebAuthnCredential(credential);
    },
};

// ---------------------------------------------------------------------------
// Recorder (window / tab / navigation tracking, event assembly)
// ---------------------------------------------------------------------------
class Recorder {
    incognito = false;
    recordingDelay = 0;
    recordingWindowId = -1;
    recordingTabId = -1;
    tabIdLookup = Object.create(null);

    #events = [];
    #recording = false;
    #extraWindowIds = [];
    #completing = false;

    async start(delay) {
        this.recordingDelay = delay;
        log("Recording...");
        this.#events = [];

        if (await browser.extension.isAllowedIncognitoAccess()) {
            await this.launchRecordingWindow(true);
        } else {
            const settings = await browser.storage.sync.get(BYPASS_INCOGNITO);
            if (settings[BYPASS_INCOGNITO]) await this.launchRecordingWindow(false);
        }
    }

    async launchRecordingWindow(incognito) {
        this.incognito = incognito;
        const win = await browser.windows.create({ incognito, focused: true, state: "maximized" });
        this.recordingWindowId = win.id;
        const tabs = win.tabs?.length ? win.tabs : await browser.tabs.query({ windowId: win.id });
        this.recordingTabId = tabs[0].id;

        browser.tabs.onCreated.addListener(this.tabCreatedListener);
        browser.windows.onCreated.addListener(this.windowCreatedListener);
        browser.windows.onRemoved.addListener(this.windowRemovedListener);
        browser.webNavigation.onDOMContentLoaded.addListener(this.tabListener);
        browser.action.setIcon({ path: imageUrl("WebApp-Recorder-recording-icon.png") });
        browser.webNavigation.onBeforeNavigate.addListener(this.manualUrlListener);
        browser.webNavigation.onCommitted.addListener(this.manualUrlListener);

        this.tabIdLookup[this.recordingTabId] = win.id;
        this.saveEvent({
            name: EXTENSION_NAME,
            version: browser.runtime.getManifest().version,
            recordingDelay: this.recordingDelay,
            eventType: "start",
            platform: navigator.platform,
            iframes: [],
            windows: [{ windowId: win.id }],
            tabs: [{ tabId: this.recordingTabId, windowId: win.id }],
        });
    }

    isRecording() {
        return this.#recording;
    }

    setRecordingState(state) {
        this.#recording = state;
    }

    triggersNavigation(event) {
        return !(!event || event.eventType === "start" || event.eventType === "goto");
    }

    tabIdToWindowId(tabId) {
        return this.tabIdLookup[tabId];
    }

    lastEvent() {
        return this.#events[this.#events.length - 1];
    }

    saveEvent(event) {
        this.#events.push(event);
    }

    storeData(events) {
        this.#events = this.#events.concat(events);
    }

    installed() {
        log("Extension installed");
    }

    // -- navigation ---------------------------------------------------------
    manualUrlListener = (details) => {
        if (!/^https?:/.test(details.url)) return;

        const now = new Date();
        const gotoEvent = {
            date: now,
            timestamp: +now,
            eventType: "goto",
            url: details.url,
            triggersNavigation: true,
            frameId: details.frameId,
            tabId: details.tabId,
            windowId: this.tabIdToWindowId(details.tabId),
        };
        const last = this.lastEvent();

        if (details.transitionQualifiers && details.transitionQualifiers.includes("client_redirect")) {
            const redirectEvent = {
                date: now,
                timestamp: +now,
                url: details.url,
                eventType: "clientSideRedirect",
                frameId: details.frameId,
                tabId: details.tabId,
                windowId: this.tabIdToWindowId(details.tabId),
            };
            if (last && this.triggersNavigation(last)) last.triggersNavigation = true;
            this.saveEvent(redirectEvent);
        } else if (last && this.triggersNavigation(last)) {
            last.triggersNavigation = true;
            const navigateEvent = {
                date: now,
                timestamp: +now,
                eventType: "userNavigate",
                url: details.url,
                frameId: details.frameId,
                tabId: details.tabId,
                windowId: this.tabIdToWindowId(details.tabId),
            };
            this.addStartUrl(details.url, details.tabId);
            this.saveEvent(navigateEvent);
        }

        if (details.transitionType === "auto_bookmark") {
            gotoEvent.fromAddressBar = true;
            gotoEvent.url = last ? last.url : gotoEvent.url;
            this.addStartUrl(details.url, details.tabId);
        } else if (
            details.transitionQualifiers &&
            details.transitionQualifiers.includes("from_address_bar") &&
            last &&
            last.eventType === "goto"
        ) {
            gotoEvent.fromAddressBar = true;
            gotoEvent.url = last.url;
            this.addStartUrl(details.url, details.tabId);
        } else {
            gotoEvent.fromAddressBar = false;
        }

        if (last && last.fromAddressBar && gotoEvent.fromAddressBar && gotoEvent.url === last.url) return;
        this.saveEvent(gotoEvent);
    };

    addStartUrl(url, tabId) {
        const tab = this.#events[0].tabs.find((t) => t.tabId === tabId);
        if (tab && !tab.attributes) tab.attributes = { firstUrl: url };
    }

    addInfoToFirstEvent(kind, info, _idKey, id) {
        const first = this.#events[0];
        if (kind === "tabs") {
            if (!first.tabs.find((t) => t.tabId === id)) first.tabs.push(info);
        } else if (!first.windows.find((w) => w.windowId === id)) {
            first.windows.push(info);
        }
    }

    // -- tabs / windows -----------------------------------------------------
    tabCreatedListener = async (tab) => {
        if (!this.isRecording()) return;
        if (tab.windowId < this.recordingWindowId || (this.incognito && !tab.incognito)) return;

        const tabs = await browser.tabs.query({ windowId: tab.windowId });
        if (!tabs.length) return;

        this.addInfoToFirstEvent(
            "tabs",
            { tabId: tab.id, windowId: tab.windowId, openerTabId: tab.openerTabId },
            "tabId",
            tab.id
        );
        this.tabIdLookup[tab.id] = tab.windowId;

        browser.scripting
            .executeScript({
                target: { tabId: tabs[0].id },
                func: (windowId, tabId) => {
                    window.recorder.collectEvents({
                        createdTab: true,
                        triggersNavigation: true,
                        opensNewContext: true,
                        windowId,
                        tabId,
                    });
                },
                args: [tab.windowId, tabs[0].id],
                injectImmediately: true,
            })
            .catch((err) => log("Failed to collect events. error:", err));
    };

    windowCreatedListener = async (win) => {
        if (!this.isRecording()) return;
        if (win.id < this.recordingWindowId || (this.incognito && !win.incognito)) return;
        if (win.id === this.recordingWindowId) return;

        this.#extraWindowIds.push(win.id);

        browser.tabs.query({ windowId: win.id }).then((tabs) => {
            if (tabs[0]) this.tabIdLookup[tabs[0].id] = win.id;
        });

        const recordingTabs = await browser.tabs.query({ windowId: this.recordingWindowId });
        if (!recordingTabs.length) return;

        this.addInfoToFirstEvent("windows", { windowId: win.id, state: win.state }, "windowId", win.id);
        browser.scripting
            .executeScript({
                target: { tabId: recordingTabs[0].id },
                func: (windowId, tabId) => {
                    window.recorder.collectEvents({
                        createdWindow: true,
                        triggersNavigation: true,
                        opensNewContext: true,
                        windowId,
                        tabId,
                    });
                },
                args: [win.id, recordingTabs[0].id],
                injectImmediately: true,
            })
            .catch((err) => log("Failed to collect events. error:", err));
    };

    findLastEvent(excludePattern, callback) {
        const count = this.#events.length;
        if (!count) return;
        for (let i = count - 1; i > 0; i--) {
            if (this.#events[i] && !excludePattern.test(this.#events[i].eventType)) {
                callback(i, this.#events);
                return;
            }
        }
    }

    windowRemovedListener = (windowId) => {
        if (this.isRecording() && windowId !== this.recordingWindowId && this.#events.length) {
            this.findLastEvent(/^(?:goto|userNavigate)$/, (index, events) => {
                events[index].closesContext = true;
            });
        }
        if (this.isRecording() && windowId === this.recordingWindowId) {
            browser.storage.session.set({ [RECORDING]: false });
            this.complete();
        }
    };

    tabListener = async (details) => {
        if (!this.isRecording()) return;
        let tab;
        try {
            tab = await browser.tabs.get(details.tabId);
        } catch {
            return;
        }
        if (tab.windowId < this.recordingWindowId || (this.incognito && !tab.incognito)) return;

        browser.scripting
            .executeScript({
                target: { tabId: details.tabId, frameIds: [details.frameId] },
                func: (frameId, tabId, delay) => {
                    window.recorder.start(frameId, tabId, delay);
                },
                args: [details.frameId, details.tabId, this.recordingDelay],
                injectImmediately: true,
            })
            .catch((err) => log("Failed to execute JavaScript:", err));
    };

    // -- page <-> background plumbing ---------------------------------------
    collectIframeInfo(frameId, windowId, info) {
        const first = this.#events[0];
        if (first.iframes.some((f) => f.frameId === frameId)) return;
        first.iframes.push({ frameId, createdByWindowId: windowId, ...info });
    }

    addWindowTabInformation(events) {
        const first = this.#events[0];
        for (let i = 0; i < events.length; i++) {
            const event = events[i];
            if (event.eventType !== "click" && event.eventType !== "rightClick") continue;
            if (event.createdTabId) {
                for (const tab of first.tabs) {
                    if (tab.tabId === event.createdTabId && tab.windowId === event.windowId && event.opensNewContext) {
                        tab.createdByEvent = i;
                        break;
                    }
                }
            } else if (event.createdWindowId) {
                for (const win of first.windows) {
                    if (win.windowId === event.createdWindowId && event.opensNewContext) {
                        win.createdByEvent = i;
                        break;
                    }
                }
            }
        }
    }

    addWebAuthnCredential(credential) {
        const first = this.#events[0];
        if (!first) return;
        if (!first.webAuthnCredentials) first.webAuthnCredentials = [];
        const index = first.webAuthnCredentials.findIndex((c) => c.credentialId === credential.credentialId);
        if (index >= 0) first.webAuthnCredentials[index] = credential;
        else first.webAuthnCredentials.push(credential);
    }

    pageUnload() {
        browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
            if (!tabs.length) return;
            if (!tabs[0]) {
                log("Unable to collect events tab doesn't exist");
                return;
            }
            browser.scripting
                .executeScript({
                    target: { tabId: tabs[0].id },
                    func: () => {
                        window.recorder.collectEvents();
                    },
                    injectImmediately: true,
                })
                .catch((err) => log("Failed to collect events. error:", err));
        });
    }

    async finish() {
        log("Stopped recording.");
        const tabs = await browser.tabs.query({ windowId: this.recordingWindowId });
        if (tabs.length) {
            browser.scripting
                .executeScript({
                    target: { tabId: tabs[0].id },
                    func: () => {
                        window.recorder.finish();
                    },
                    injectImmediately: true,
                })
                .catch((err) => log("Error closing window", err));
        }
        browser.action.setIcon({ path: imageUrl("WebApp-Recorder-stop-icon.png") });
    }

    async sendWarningMessage() {
        if (!this.isRecording()) return;
        const tabs = await browser.tabs.query({ windowId: this.recordingWindowId });
        if (!tabs.length) return;
        browser.scripting
            .executeScript({
                target: { tabId: tabs[0].id },
                func: () => {
                    window.recorder.showWarningMessage();
                },
                injectImmediately: true,
            })
            .catch((err) => log("Failed to send warning message", err));
    }

    /** Drop synthetic "goto" events unless they came from the address bar; collapse consecutive ones. */
    filterEvents(events) {
        const result = [];
        for (let i = 0; i < events.length; i++) {
            const event = events[i];
            const previous = events[i - 1];
            if (event.eventType === "goto") {
                if (!event.fromAddressBar) continue;
                if (previous && previous.eventType === "goto") {
                    const tail = result[result.length - 1];
                    if (tail && tail.eventType !== "start") result[result.length - 1] = events[i];
                    else result.push(events[i]);
                } else {
                    result.push(events[i]);
                }
            } else {
                result.push(events[i]);
            }
        }
        return result;
    }

    async complete() {
        if (this.#completing) return;
        this.#completing = true;

        const events = this.filterEvents(this.#events);
        this.addWindowTabInformation(events);

        let json = "";
        if (this.#events.length) {
            try {
                json = JSON.stringify(events, undefined, 4);
                browser.storage.session.set({ [LAST_RECORDING]: json });
            } catch (err) {
                log("Failed to save JSON" + err);
            }
        }

        browser.notifications.create("notify", {
            iconUrl: imageUrl("WebApp-Recorder-128.png"),
            title: EXTENSION_NAME,
            type: "basic",
            message: "Your recording has finished and has been copied to your clipboard.",
        });
        try {
            await copyToClipboard(json);
        } catch (err) {
            log("Failed to copy recording to the clipboard", err);
        }

        this.#events = [];
        this.removeListeners();
        this.setRecordingState(false);
        browser.action.setIcon({ path: imageUrl("WebApp-Recorder-stop-icon.png") });

        for (const id of this.#extraWindowIds) await browser.windows.remove(id).catch(() => {});
        this.#extraWindowIds = [];
        if (this.recordingWindowId > 0) await browser.windows.remove(this.recordingWindowId).catch(() => {});

        try {
            const popupWindowId = (await browser.storage.session.get(POPUP_WINDOW_ID))[POPUP_WINDOW_ID];
            if (popupWindowId !== undefined) {
                await browser.windows.update(popupWindowId, { focused: true });
                await browser.action.openPopup({ windowId: popupWindowId });
            } else {
                await browser.action.openPopup();
            }
        } catch {
            // openPopup() can be refused by the browser; the user can still click the toolbar button.
        }
        this.#completing = false;
    }

    removeListeners() {
        browser.tabs.onCreated.removeListener(this.tabCreatedListener);
        browser.windows.onCreated.removeListener(this.windowCreatedListener);
        browser.windows.onRemoved.removeListener(this.windowRemovedListener);
        browser.webNavigation.onDOMContentLoaded.removeListener(this.tabListener);
        browser.webNavigation.onBeforeNavigate.removeListener(this.manualUrlListener);
        browser.webNavigation.onCommitted.removeListener(this.manualUrlListener);
    }
}

const recorder = new Recorder();

// ---------------------------------------------------------------------------
// WebAuthn shim registration (content scripts are only injected on demand)
// ---------------------------------------------------------------------------
const WEBAUTHN_SCRIPT_IDS = ["webauthn-bridge", "webauthn-shim"];
const WEB_MATCHES = ["http://*/*", "https://*/*"];
let registering = null;

function registerWebAuthnScripts() {
    if (registering) return registering;
    registering = (async () => {
        const existing = await browser.scripting.getRegisteredContentScripts({ ids: WEBAUTHN_SCRIPT_IDS });
        if (existing.length > 0) return;

        await browser.scripting.registerContentScripts([
            {
                id: "webauthn-bridge",
                js: ["content-scripts/webauthn/webauthn-bridge.js"],
                matches: WEB_MATCHES,
                runAt: "document_start",
                world: "ISOLATED",
                allFrames: true,
                persistAcrossSessions: false,
            },
            {
                id: "webauthn-shim",
                js: ["content-scripts/webauthn/webauthn-shim.js"],
                matches: WEB_MATCHES,
                runAt: "document_start",
                world: "MAIN",
                allFrames: true,
                persistAcrossSessions: false,
            },
        ]);

        // Also inject into pages that are already open.
        const tabs = await browser.tabs.query({ url: WEB_MATCHES });
        for (const tab of tabs) {
            if (!tab.id) continue;
            browser.scripting
                .executeScript({
                    target: { tabId: tab.id, allFrames: true },
                    world: "ISOLATED",
                    files: ["content-scripts/webauthn/webauthn-bridge.js"],
                })
                .catch(() => {});
            browser.scripting
                .executeScript({
                    target: { tabId: tab.id, allFrames: true },
                    world: "MAIN",
                    files: ["content-scripts/webauthn/webauthn-shim.js"],
                })
                .catch(() => {});
        }
    })().finally(() => {
        registering = null;
    });
    return registering;
}

async function unregisterWebAuthnScripts() {
    await browser.scripting.unregisterContentScripts({ ids: WEBAUTHN_SCRIPT_IDS }).catch(() => {});
}

browser.storage.session.get(WEBAUTHN_ENABLED).then((stored) => {
    if (stored[WEBAUTHN_ENABLED]) registerWebAuthnScripts();
});

// ---------------------------------------------------------------------------
// Privacy settings (disable autofill / password saving while recording)
// ---------------------------------------------------------------------------
const PRIVACY_SETTINGS = ["autofillAddressEnabled", "autofillCreditCardEnabled", "passwordSavingEnabled"];

async function disablePrivacySettings() {
    for (const name of PRIVACY_SETTINGS) {
        const setting = browser.privacy?.services?.[name];
        if (!setting) continue; // not exposed by this browser (Firefox only has passwordSavingEnabled)
        try {
            await setting.set({ value: false });
        } catch (err) {
            log(`Failed to disable ${name}`, err);
        }
    }
}

async function restorePrivacySettings() {
    for (const name of PRIVACY_SETTINGS) {
        const setting = browser.privacy?.services?.[name];
        if (!setting) continue;
        try {
            await setting.clear({});
        } catch (err) {
            log(`Failed to restore ${name}`, err);
        }
    }
}

// ---------------------------------------------------------------------------
// Platform (HTTP) authentication warning
// ---------------------------------------------------------------------------
let platformAuthSeen = false;

browser.webRequest.onAuthRequired.addListener(
    (details) => {
        if (details.frameId === 0 && !details.isProxy) platformAuthSeen = true;
    },
    { urls: ["https://*/*", "http://*/*"], types: ["main_frame"] }
);

browser.webRequest.onCompleted.addListener(
    () => {
        if (platformAuthSeen && recorder.isRecording()) {
            setTimeout(() => recorder.sendWarningMessage(), 500);
        }
    },
    { urls: ["https://*/*", "http://*/*"], types: ["main_frame"] }
);

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
browser.runtime.onInstalled.addListener(() => recorder.installed());
browser.runtime.onStartup.addListener(() => restorePrivacySettings());

browser.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) recorder.pageUnload();
});

// The popup drives the recorder purely through storage.session.
browser.storage.onChanged.addListener(async (changes, area) => {
    if (area !== "session") return;

    if (WEBAUTHN_ENABLED in changes) {
        if (changes[WEBAUTHN_ENABLED].newValue) await registerWebAuthnScripts();
        else await unregisterWebAuthnScripts();
    }

    if (!changes[RECORDING]) return;
    const recording = changes[RECORDING].newValue;
    if (recording) {
        await registerWebAuthnScripts();
        recorder.setRecordingState(recording);
        await disablePrivacySettings();
        recorder.start(0);
    } else {
        platformAuthSeen = false;
        await restorePrivacySettings();
        recorder.finish();
        await unregisterWebAuthnScripts();
    }
});

// ---------------------------------------------------------------------------
// Messages from content scripts / bridge
// ---------------------------------------------------------------------------
function annotateEvents(events, sender, isIframe) {
    for (const event of events) {
        event.frameId = sender.frameId;
        if (sender.tab?.id) event.tabId = sender.tab.id;
        event.windowId = sender.tab?.windowId;
        if (typeof event.url !== "string" || !/^https?:/.test(event.url)) event.url = sender.url;
        event.isIframe = !!isIframe;
    }
    return events;
}

function showPasskeyCapturedToast(tabId) {
    const version = browser.runtime.getManifest().version;
    browser.scripting
        .executeScript({
            target: { tabId },
            func: (title, message, versionLabel) => {
                const FONT =
                    'Roboto,-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif';
                const el = (tag, css, text) => {
                    const node = document.createElement(tag);
                    node.style.cssText = css;
                    if (text !== undefined) node.textContent = text;
                    return node;
                };
                const box = el(
                    "div",
                    "position:fixed;top:20px;right:20px;z-index:2147483647;background:#fff;padding:20px;" +
                        "border-radius:8px;box-shadow:0 0 10px rgba(0,0,35,0.1);opacity:0;transition:opacity .3s;" +
                        "display:flex;flex-direction:column;gap:30px;max-width:340px;"
                );
                const header = el("div", "display:flex;align-items:center;justify-content:space-between;");
                header.appendChild(el("span", `font:500 18px/1.3 ${FONT};color:#000023;`, "Login Recorder for Burp Suite"));
                header.appendChild(el("span", `font:400 14px/1.4 ${FONT};color:#676667;`, versionLabel));
                box.appendChild(header);

                const body = el("div", "display:flex;flex-direction:column;gap:20px;");
                const row = el("div", "display:flex;align-items:center;gap:10px;");
                row.appendChild(el("span", `font:500 24px/1.4 ${FONT};color:#000023;`, title));

                const SVG_NS = "http://www.w3.org/2000/svg";
                const svg = document.createElementNS(SVG_NS, "svg");
                svg.setAttribute("width", "23");
                svg.setAttribute("height", "23");
                svg.setAttribute("viewBox", "0 0 23 23");
                svg.setAttribute("fill", "none");
                svg.style.cssText = "flex-shrink:0;";
                const circle = document.createElementNS(SVG_NS, "circle");
                circle.setAttribute("cx", "11.5");
                circle.setAttribute("cy", "11.5");
                circle.setAttribute("r", "11.5");
                circle.setAttribute("fill", "#0094FF");
                svg.appendChild(circle);
                const tick = document.createElementNS(SVG_NS, "path");
                tick.setAttribute("d", "M7 11.5L10.5 15L16.5 8.5");
                tick.setAttribute("stroke", "white");
                tick.setAttribute("stroke-width", "2");
                tick.setAttribute("stroke-linecap", "round");
                tick.setAttribute("stroke-linejoin", "round");
                svg.appendChild(tick);
                row.appendChild(svg);
                body.appendChild(row);
                body.appendChild(el("span", `font:400 14px/1.4 ${FONT};color:#676667;`, message));
                box.appendChild(body);

                document.documentElement.appendChild(box);
                requestAnimationFrame(() => {
                    box.style.opacity = "1";
                });
                setTimeout(() => {
                    box.style.opacity = "0";
                    setTimeout(() => box.remove(), 300);
                }, 3000);
            },
            args: ["Passkey captured", "Return to the extension to record your login sequence.", version],
        })
        .catch(() => {});
}

async function handleWebAuthnShimRequest(message, sender) {
    try {
        const enabled = await credentialStore.isEnabled();
        if (!enabled && !recorder.isRecording()) {
            return { ok: true, response: { type: message.request.type, declined: true } };
        }
        const request = normalizeRequest(message.request);
        const response = await authenticator.handleRequest(request);
        if (request.type === "create" && !response.declined && sender.tab?.id) {
            showPasskeyCapturedToast(sender.tab.id);
        }
        return { ok: true, response };
    } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        return { ok: false, error: { name: error.name, message: error.message } };
    }
}

browser.runtime.onMessage.addListener((message, sender) => {
    switch (message.messageType) {
        case "collectEvents":
            recorder.storeData(annotateEvents(message.events, sender, message.isIframe));
            return;
        case "complete":
            recorder.complete();
            return;
        case "collectIframeInfo":
            recorder.collectIframeInfo(message.frameId, sender.tab.windowId, message.iframeInfo);
            return;
        case "webauthn-shim-request":
            return handleWebAuthnShimRequest(message, sender);
        case "stopRecording":
            browser.storage.session.set({ [RECORDING]: false });
            return;
    }
});

// ---------------------------------------------------------------------------
// Keep-alive: content scripts in the top frame open a port; pinging it keeps
// the (non-persistent) event page from being suspended mid-recording.
// ---------------------------------------------------------------------------
browser.runtime.onConnect.addListener((port) => {
    if (port.name !== "recorder-keep-alive") return;
    log("Connected to recorder-keep-alive port");
    const timer = setInterval(() => {
        try {
            port.postMessage({ status: "ping" });
        } catch (err) {
            console.error("Error sending ping", err);
        }
    }, 10000);
    port.onMessage.addListener(() => {});
    port.onDisconnect.addListener(() => {
        log("Recorder port disconnected, clearing ping interval");
        clearInterval(timer);
    });
});
