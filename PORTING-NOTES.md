# Login Recorder for Burp Suite – Firefox port

Port of the Chrome Web Store extension [Login Recorder for Burp Suite](https://chromewebstore.google.com/detail/login-recorder-for-burp-s/anpapjclbjicacakeoggghfldppbkepg) (`anpapjclbjicacakeoggghfldppbkepg`, v3.0.5, PortSwigger)
to Firefox (MV3, Firefox ≥ 128). The recorded JSON schema is unchanged, so Burp's
"Recorded login" import should accept it the same way it accepts the Chrome version's output.

## Install

- **Temporary:** `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on…* → `manifest.json`.
- **Persistent (Developer Edition/Nightly):** set `xpinstall.signatures.required = false` in
  `about:config`, then install the `.xpi` from the [latest release](https://github.com/Somchandra17/burp-login-recorder-firefox/releases/latest) via `about:addons` (⚙ → *Install Add-on From File*).
- For the clean-session mode the original uses, open `about:addons` → the extension → set **Run in Private Windows** to *Allow*.
  Otherwise use *Continue without incognito*, which records in a normal window.

## How the extension works (reversed)

| File | Role |
|---|---|
| `popup/js/popup.js` | React UI. Controls everything by writing `storage.session` keys: `recording`, `lastRecording`, `webauthnEnabled`, `webauthnCredentials`, `popupWindowId`, `passkeyLoginEnabled`; `storage.sync.bypassIncognito`. |
| `background/background.js` | Recorder state machine. When `recording` becomes `true`: opens a maximized (private) window, hooks `tabs`/`windows`/`webNavigation`, injects `recorder.start()` into every frame on DOMContentLoaded, and turns off password saving via `privacy`. When `recording` becomes `false`: flushes events, builds the JSON, stores it in `lastRecording`, copies it to the clipboard, closes the recording windows and reopens the popup. |
| `content-scripts/classes/Recorder.js` | Captures click / right-click / typing / paste / keyboard / scroll / hashchange events, with XPath, shadow-DOM, iframe and text-node metadata. Opens a `recorder-keep-alive` port. **Unchanged from the original.** |
| `content-scripts/webauthn/webauthn-shim.js` | MAIN-world override of `navigator.credentials.create/get`. **Unchanged.** |
| `content-scripts/webauthn/webauthn-bridge.js` | ISOLATED-world relay between the shim and the background. Only change: uses `browser.runtime`. |
| background authenticator | Software ES256 "platform" passkey authenticator (CBOR COSE key, `fmt: none` attestation, DER signatures). Credentials are kept in `storage.session` and embedded in the recording as `webAuthnCredentials`. |

## Firefox changes

| Chrome | Firefox port |
|---|---|
| MV3 service worker | MV3 event page (`background.scripts`); same keep-alive port. Tested: state survives the 30 s idle timeout. |
| `chrome.offscreen` clipboard document + `runtime.getContexts` | `navigator.clipboard.writeText` from the background page (`clipboardWrite`), with an `execCommand` fallback. `background/offscreen.*` removed. |
| `privacy.services.autofillAddressEnabled` / `autofillCreditCardEnabled` / `passwordSavingEnabled` | Firefox exposes only `passwordSavingEnabled`, so the other two are feature-detected and skipped. Settings are handed back with `clear()` (and on browser startup) instead of restoring a value cached when the worker started. |
| `chrome://extensions/?id=…#allow-incognito` link | Firefox blocks extensions from opening `chrome://` and `about:addons`, so the button copies `about:addons` to the clipboard and shows instructions. |
| Import passkey in the toolbar popup | Firefox closes popups when a file picker opens, so import reopens the UI in a tab (`popup.html#passkeys`). |
| `key`, `update_url`, `options_page`, `offscreen` permission | Removed. Added `browser_specific_settings.gecko`; `options_page` became `options_ui`. |

The popup bundle is otherwise unmodified: Firefox's MV3 `chrome.*` namespace supports both the callback and the promise styles it uses (verified).

## Verified in Firefox 158 (Developer Edition)

- Full record cycle in a local test site: typing, clicks, a link opening a new tab, same-tab navigation, iframe recorder start, iframe metadata, stop → `lastRecording` JSON and clipboard → recording window closed → privacy override released.
- Passkey capture: `create()` and `get()` through the MAIN-world shim; the assertion signature verifies against the returned public key; scripts unregister when capture is turned off.
- `web-ext lint`: 0 errors (2 warnings are React's own `innerHTML` use inside the vendor bundle).

## Not verified

- Popup rendering and clicks. WebDriver BiDi can't script `moz-extension://` pages; the logic was checked against the same APIs from the background page.
- Private-window recording mode. The temporary add-on had no private-browsing permission, so tests used the "Continue without incognito" path.
- `goto` events from typing in the address bar, the HTTP platform-authentication warning, `action.openPopup()` after a recording, and importing the JSON into Burp.

## Behaviour differences to know about

- Firefox `frameId`s are large numbers (e.g. `23622320129`) instead of Chrome's small integers. They stay internally consistent within a recording.
- Kept as-is from the original (upstream quirks): `createdTabId` / `createdByEvent` point at the first tab of the window, not the newly opened tab. The passkey `getPublicKey()` returns the raw EC point rather than SPKI.

## Licensing

This is a derivative of PortSwigger's proprietary extension, ported for personal/internal interoperability.
Don't publish it to AMO or redistribute it without PortSwigger's permission.
