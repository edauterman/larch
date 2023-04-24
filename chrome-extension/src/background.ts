import * as CBOR from 'cbor';

import { Browser, browser as detectBrowser } from './browser';
import {crypto_hash_sha256, from_base64_url_nopad, to_base64_url_nopad, from_base64_url, to_base64_url} from './crypto';
import EnclaveClient from './enclave_client';
import {RequestTypes, ResponseTypes} from './enums';
import { parse, stringify, webauthnParse, webauthnStringify } from './krjson';
import { Message, RequestType, Toast } from './messages';
import { BAD_APPID, checkIsRegistrableDomainSuffix, fetchAppIdUrl, verifyU2fAppId} from './origin-checker';
import * as protocol from './protocol';
import { addPresenceAndCounter, client, makeRegisterData } from './u2f';
import {getDomainFromOrigin, getOriginFromUrl} from './url';
import {createAuthenticatorDataWithAttestation, createAuthenticatorDataWithoutAttestation} from './webauthn';

const byteToHex = []; 
for (let i = 0; i < 256; ++i) {
    byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToStr(buf, numBytes) {
  const bth = byteToHex;
  var arr = []; 
  for (let i = 0; i < numBytes; i++) {
    arr.push(bth[buf[i]]);
  }
  return arr.join('');
}


async function onRequest(msg, sender) {
    console.log("IN ON REQUEST");
    if (msg.type) {
        if (msg.type === RequestTypes.REGISTER_U2F) {
            const sendResponse = getResponseSender(ResponseTypes.REGISTER_U2F, msg.requestId, sender);
            handle_u2f_register(msg, sender).then(sendResponse)
                                            .catch((e) => { console.error(e); sendResponse({ fallback: true }); });
            return;
        } else if (msg.type === RequestTypes.REGISTER_WEBAUTHN) {
            const sendResponse = getResponseSender(ResponseTypes.REGISTER_WEBAUTHN, msg.requestId, sender);
            console.log("REGISTER");
            handle_webauthn_register(msg, sender).then(sendResponse)
                                                 .catch(console.error);
            return;
        } else if (msg.type === RequestTypes.SIGN_U2F) {
            const sendResponse = getResponseSender(ResponseTypes.SIGN_U2F, msg.requestId, sender);
            handle_u2f_sign(msg, sender).then(sendResponse)
                                        .catch((e) => { console.error(e); sendResponse({ fallback: true }); });
            return;
        } else if (msg.type === RequestTypes.SIGN_WEBAUTHN) {
            const sendResponse = getResponseSender(ResponseTypes.SIGN_WEBAUTHN, msg.requestId, sender);
            handle_webauthn_sign(msg, sender).then(sendResponse)
                                            .catch(console.error);
            return;
        }
    }
    if (typeof(msg) === 'string') {
        msg = await parse(Message, msg);
    }
    return onMessage(msg);
}

async function onMessage(m: Message) {
    console.log("ON MESSAGE");
    const c = await client;
    if (m.request) {
        switch (m.request.ty) {
            case RequestType.getState: {
                sendFullStateToPopup(c);
                break;
            }
            case RequestType.refreshPopup: {
                await c.refreshPopup();
                break;
            }
            case RequestType.unpair: {
                await c.unpair(true);
                sendFullStateToPopup(c);
                break;
            }
        }
    }
}

switch (detectBrowser()) {
    case Browser.safari:
        safari.application.addEventListener('message', (evt) => {
            onRequest((evt as any).message, evt.target);
        });
        (safari.extension.globalPage.contentWindow as any).krRequestGlobalPage = onRequest;
        break;
    default:
        chrome.runtime.onMessage.addListener(onRequest);
}

function getFetcher(sender: chrome.runtime.MessageSender) {
    switch (detectBrowser()) {
        case Browser.safari:
            return fetchAppIdUrl;
        case Browser.chrome:
            return fetchAppIdUrl;
        default:
            return function fetch(url: string): Promise<string> {
                return new Promise(function(resolve, reject) {
                    const msg = {
                        type: 'url_fetch',
                        url,
                    };
                    chrome.tabs.sendMessage(sender.tab.id, msg, (response) => {
                        if (response == null) {
                            reject(chrome.runtime.lastError);
                        } else {
                            resolve(String(response));
                        }
                    });
                });
            };
    }
}

function getResponseSender(responseType: string,
                           requestId: number,
                           sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {
    let responseSent = false;
    return function(responseData: object) {
        if (responseSent) {
            console.warn('Attempting to send multiple responses');
            return;
        }
        responseSent = true;
        const response = {
            data: {
                requestId,
                responseData,
            },
            type: responseType,
        };
        sendIfTabActive(sender, response);
    };
}

async function handle_webauthn_register(msg: any,
                                        sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {

    const options: CredentialCreationOptions = webauthnParse(msg.options);
    const pkOptions = options.publicKey;

    const origin = getOriginFromUrl(sender.url);
    if (pkOptions.rp.id && !checkIsRegistrableDomainSuffix(origin, pkOptions.rp.id)) {
        throw new Error('SecurityError');
    }
    const rpId = pkOptions.rp.id || getDomainFromOrigin(origin);
    if (pkOptions.excludeCredentials) {
        for (const excludeCredential of pkOptions.excludeCredentials) {
            const keyHandle = new Uint8Array(excludeCredential.id as ArrayBuffer);
        }
    }
    console.log("---> RP ID");
    console.log(rpId);

    let foundNistKeyType = false;
    if (pkOptions.pubKeyCredParams) {
        for (const params of pkOptions.pubKeyCredParams) {
            // webauthn.io sets alg to the string '-7', so we accept anything that coerces to -7
            // tslint:disable-next-line:triple-equals
            if (params.alg == -7 && params.type === 'public-key') {
                foundNistKeyType = true;
                break;
            }
        }
        if (!foundNistKeyType) {
            throw new Error('only nistp256 keys supported');
        }
    }

    const clientDataNoPad = JSON.stringify({
        challenge: await to_base64_url_nopad(new Uint8Array(pkOptions.challenge as any)), // no_pad
        clientExtensions: {},
        hashAlgorithm: 'SHA-256',
        origin,
        type: 'webauthn.create',
    });
    const clientDataB64NoPad = await to_base64_url_nopad(clientDataNoPad); // no_pad

    const challenge = await crypto_hash_sha256(clientDataNoPad);
    const challengeBytes = await to_base64_url(challenge.slice(0, 32)); // no pad
    console.log("waiting to enroll");
    var response = {"key_handle": "0", "public_key": "0", "attestation_certificate": "0", "signature": "0"};
    var returned = false;
    chrome.runtime.sendNativeMessage("agent",{
            type: "enroll_helper_request",
            app_id: await to_base64_url(await crypto_hash_sha256(rpId)),
            challenge: challengeBytes,
        },
        function(resp) {
            console.log(resp);
            response = JSON.parse(JSON.stringify(resp));
            response = resp;
            returned = true;
            console.log("Received response");
        }
    );
    while(returned == false) {
        console.log("looping");
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    //await new Promise(resolve => setTimeout(resolve, 10000))
    console.log("got enroll");

    const u2fRegisterResponse = response;
    console.log(response);
    //const u2fRegisterResponse = response.u2f_register_response;

    const authenticatorData = await createAuthenticatorDataWithAttestation(rpId,
                                                                           10, /*u2fRegisterResponse.counter,*/
                                                                           await from_base64_url(u2fRegisterResponse.key_handle),
                                                                           await from_base64_url(u2fRegisterResponse.public_key));
    console.log(authenticatorData);

    let attestationObject: ArrayBuffer;
    if (pkOptions.attestation == null || pkOptions.attestation === 'none') {
        console.log("attestation = none");
        attestationObject = CBOR.encodeCanonical({
            attStmt: {},
            authData: new Buffer(authenticatorData.buffer),
            fmt: 'none',
        }).buffer;
    } else {
        console.log("attestation != none");
        attestationObject = CBOR.encodeCanonical({
            attStmt: {
                sig: new Buffer(u2fRegisterResponse.signature), /* buffer */
                x5c: [new Buffer(u2fRegisterResponse.attestation_certificate)], /* buffer */
            },
            authData: new Buffer(authenticatorData.buffer),
            fmt: 'fido-u2f',
        }).buffer;
    }
    console.log(attestationObject);

    const credential: PublicKeyCredential = {
        id: await to_base64_url_nopad(await from_base64_url(u2fRegisterResponse.key_handle)),
        rawId: (await from_base64_url(u2fRegisterResponse.key_handle)).buffer, /* buffer */
        response: {
            attestationObject,
            clientDataJSON: (await from_base64_url_nopad(clientDataB64NoPad)).buffer,
        },
        type: 'public-key',
    };
    console.log(credential);

    const authenticatedResponseData = {
        credential: webauthnStringify(credential),
    };
    console.log(authenticatedResponseData);
    return authenticatedResponseData;
}

async function handle_u2f_register(msg: any, sender: chrome.runtime.MessageSender | browser.runtime.MessageSender) {
    const fetcher = getFetcher(sender);
    const origin = getOriginFromUrl(sender.url);
    const appId = msg.appId
        || ((msg.registerRequests && msg.registerRequests.length > 0) ? msg.registerRequests[0].appId : null)
        || origin;

    try {
        await verifyU2fAppId(origin, appId, fetcher);
    } catch (err) {
        console.error(err);
        return {errorCode: BAD_APPID};
    }

    const c = await client;

    const existingKeyHandles: string[] = [];
    if (msg.registeredKeys) {
        for (const registeredKey of msg.registeredKeys) {
            existingKeyHandles.push(registeredKey.keyHandle);
        }
    }
    if (msg.signRequests) {
        for (const signRequest of msg.signRequests) {
            existingKeyHandles.push(signRequest.keyHandle);
        }
    }
    for (const existingKeyHandle of existingKeyHandles) {
        try {
            const keyHandle = await from_base64_url_nopad(existingKeyHandle);
            if (await c.mapKeyHandleToMatchingAppId(keyHandle, { appId })) {
                //  already registered
                return { fallback: true };
            }
        } catch (e) {
            console.error(e);
        }
    }

    let serverChallenge: string;
    let clientData: string;

    //  TODO: detect U2F_V2/V1 requests
    serverChallenge = msg.registerRequests[0].challenge;
    clientData = JSON.stringify({
        challenge: serverChallenge,
        cid_pubkey: 'unused',
        origin,
        typ: 'navigator.id.finishEnrollment',
    });

    const challenge = await crypto_hash_sha256(clientData);

    console.log("think going to enroll?");
    var response;
    chrome.runtime.sendNativeMessage("agent",{
            type: "enroll_helper_request",
            app_id: appId,
            challenge,
        },
        function(resp) {
            response = resp;
            console.log("Received response");
        }
    );
    console.log("got enroll");
    console.log("got resp");
    if (!response.u2f_register_response) {
        throw new Error('no u2f_register_response');
    }
    if (response.u2f_register_response.error) {
        throw response.u2f_register_response.error;
    }

    const authenticatedResponseData = {
        clientData: await to_base64_url_nopad(clientData),
        keyHandle: await to_base64_url_nopad(response.u2f_register_response.key_handle),
        registrationData: await to_base64_url_nopad(makeRegisterData(response.u2f_register_response)),
        version: 'U2F_V2',
    };
    return authenticatedResponseData;
}

async function handle_webauthn_sign(msg: any, sender: chrome.runtime.MessageSender) {
    const c = await client;
    const fetcher = getFetcher(sender);

    const pkOptions = webauthnParse(msg.options).publicKey;
    console.log("PUB KEY");
    console.log(pkOptions);

    const origin = getOriginFromUrl(sender.url);

    let keyHandle: Uint8Array;
    let matchingAppId: string;
    const rpId: string = pkOptions.rpId || getDomainFromOrigin(origin);
    {
        let appId: string;
        if (pkOptions.extensions && pkOptions.extensions.appid) {
            try {
                await verifyU2fAppId(origin, pkOptions.extensions.appid, fetcher);
                appId = pkOptions.extensions.appid;
            } catch (err) {
                console.error(err);
                return {errorCode: BAD_APPID};
            }
        }
        if (pkOptions.rpId && !checkIsRegistrableDomainSuffix(origin, pkOptions.rpId)) {
            throw new Error('SecurityError');
        }
        //const rpId: string = pkOptions.rpId || getDomainFromOrigin(origin);

        console.log(pkOptions.allowCredentials);
        for (const credential of pkOptions.allowCredentials) {
            const id = credential.id;
            console.log(credential);
            console.log("ID");
            console.log(id);
            console.log("appID");
            console.log(appId);
            console.log("rpID");
            console.log(rpId);
            keyHandle = id;
            matchingAppId = rpId;
            break;
            /*matchingAppId = await c.mapKeyHandleToMatchingAppId(id, { appId, rpId });
            if (matchingAppId) {
                keyHandle = id;
                break;
            }*/
        }
    }
    if (!keyHandle) {
        throw new Error('Krypton not registered with this key handle');
    }
    console.log("Got a good key handle");

    const clientData = JSON.stringify({
        challenge: await to_base64_url_nopad(pkOptions.challenge),
        clientExtensions: pkOptions.extensions,
        hashAlgorithm: 'SHA-256',
        origin,
        type: 'webauthn.get',
    });
    const clientDataB64 = await to_base64_url_nopad(clientData);

    const challenge = await crypto_hash_sha256(clientData);

    var response = {"counter": 0, "signature": "0"};
    var returned = false;
    const challengeBytes = await to_base64_url(challenge.slice(0, 32)); // no pad
    const keyHandleBytes = await to_base64_url(keyHandle); // no pad
    chrome.runtime.sendNativeMessage("agent",{
            type: "sign_helper_request",
            app_id: await to_base64_url(await crypto_hash_sha256(rpId)),
            challenge: challengeBytes,
            key_handle: keyHandleBytes,
        },
        function(resp) {
            response = resp;
            returned = true;
            console.log("Received response");
        }
    );
    while (returned == false) {
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    console.log("received sign response"); 

    const u2fSignResponse = response;

    const authenticatorData = await createAuthenticatorDataWithoutAttestation(rpId, 11);
    //const authenticatorData = await createAuthenticatorDataWithoutAttestation(rpId, u2fSignResponse.counter);

    const credential: PublicKeyCredential = {
        id: await to_base64_url_nopad(keyHandle),
        rawId: keyHandle.buffer,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: (await from_base64_url_nopad(clientDataB64)).buffer,
            signature: (await from_base64_url(u2fSignResponse.signature)).buffer,
            userHandle: new ArrayBuffer(0),
        },
        type: 'public-key',
    };

    const authenticatedResponseData = {
        credential: webauthnStringify(credential),
    };
    return authenticatedResponseData;
}

async function handle_u2f_sign(msg: any, sender: chrome.runtime.MessageSender) {
    const origin = getOriginFromUrl(sender.url);
    const fetcher = getFetcher(sender);

    const c = await client;
    //  unify both request formats into registeredKeys
    if (msg.signRequests && !msg.registeredKeys) {
        if (msg.signRequests.length === 0) {
            return {};
        }
        const registeredKeys = [];
        for (const signRequest of msg.signRequests) {
            registeredKeys.push({
                appId: signRequest.appId,
                challenge: signRequest.challenge,
                keyHandle: signRequest.keyHandle,
            });
        }
        msg.registeredKeys = registeredKeys;
    }

    let matchingAppId;
    let keyHandle;
    let serverChallenge;
    {
        for (const registeredKey of msg.registeredKeys) {
            const keyHandleBytes = await from_base64_url_nopad(registeredKey.keyHandle);
            const potentialAppId: string = registeredKey.appId || msg.appId || origin;
            const appId = await c.mapKeyHandleToMatchingAppId(keyHandleBytes, {appId: potentialAppId});
            if (appId) {
                keyHandle = keyHandleBytes;
                serverChallenge = registeredKey.challenge || msg.challenge;
                matchingAppId = appId;
                break;
            }
        }
    }
    if (!keyHandle) {
        return {fallback: true};
    }

    try {
        await verifyU2fAppId(origin, matchingAppId, fetcher);
    } catch (err) {
        console.error(err);
        return {errorCode: BAD_APPID};
    }

    const clientData = JSON.stringify({
        challenge: serverChallenge,
        cid_pubkey: 'unused',
        origin: getOriginFromUrl(sender.url),
        typ: 'navigator.id.getAssertion',
    });

    const challenge = await crypto_hash_sha256(clientData);

    var response;
    chrome.runtime.sendNativeMessage("agent",{
            type: "send_helper_request",
            app_id: matchingAppId,
            challenge,
            key_handle: keyHandle,
        },
        function(resp) {
            response = resp;
            console.log("Received response");
        }
    );
    console.log("got sign response back");
 
    if (!response.u2f_authenticate_response) {
        throw new Error('no u2f_authenticate_response');
    }
    if (response.u2f_authenticate_response.error) {
        throw response.u2f_authenticate_response.error;
    }

    const signatureData = await to_base64_url_nopad(
        addPresenceAndCounter(response.u2f_authenticate_response),
    );
    const authenticatedResponseData = {
        clientData: await to_base64_url_nopad(clientData),
        keyHandle: await to_base64_url_nopad(keyHandle),
        signatureData,
    };
    return authenticatedResponseData;
}

function sendStates(c: EnclaveClient) {
    sendFullStateToPopup(c);
}

function sendToPopup(o: any) {
    switch (detectBrowser()) {
        case Browser.safari:
            const sendFn = (safari.extension.globalPage.contentWindow as any).krSendToPopup;
            if (sendFn) {
                sendFn(o);
            }
            break;
        default:
            chrome.runtime.sendMessage(stringify(o));
    }
}

function sendFullStateToPopup(c: EnclaveClient) {
    const r = c.getState();
    sendToPopup(r);
}

function sendPending(s: string) {
    const t = new Toast();
    t.pending = s;
    const m = Message.newToast(t);
    sendMessageToActiveTab(m);
}

async function sendMessageToActiveTab(m: Message) {
    sendToActiveTab(await stringify(m));
}

async function sendIfTabActive(sender: chrome.runtime.MessageSender | browser.runtime.MessageSender, o: any) {
    switch (detectBrowser()) {
        case Browser.safari:
            (sender as any).page.dispatchMessage(o.type, o);
            return;
        default:
            chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
                if (tabs[0]) {
                    if (tabs[0].id === sender.tab.id) {
                        chrome.tabs.sendMessage(
                            sender.tab.id,
                            o,
                        );
                    } else {
                        console.error('sender tab not active');
                    }
                } else {
                    console.error('no tab active');
                }
            });
    }
}

async function sendToActiveTab(s: string) {
    switch (detectBrowser()) {
        case Browser.safari:
            //  TODO: not yet implemented
            return;
        default:
            chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
                chrome.tabs.sendMessage(
                    tabs[0].id,
                    s,
                );
            });
    }
}

const UA_WINDOWS_CHROME =
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.2526.73 Safari/537.36';
function make_ua_spoofer(userAgent: string, referers?: [string], origins?: [string]) {
    return function user_agent_handler(details) {
        if (referers) {
            if (!details.requestHeaders.some(
                (header) => header.name === 'Referer' && referers.indexOf(header.value) >= 0)) {
                return;
            }
        }

        if (origins) {
            if (!details.requestHeaders.some(
                (header) => header.name === 'Origin' && origins.indexOf(header.value) >= 0)) {
                return;
            }
        }

        for (const header of details.requestHeaders) {
            if (header.name === 'User-Agent') {
                /* tslint:disable */
                header.value = userAgent;
                /* tslint:enable */
                break;
            }
        }

        return { requestHeaders: details.requestHeaders };
    };
}

const fbFilterCatchAll = [
    '*://*.facebook.com/*',
    '*://*.facebook.net/*',
    '*://*.fbcdn.net/*',
];
const fbFilterSpecific = [
    '*://www.facebook.com/checkpoint/?next',
];

switch (detectBrowser()) {
    case Browser.firefox:
        browser.webRequest.onBeforeSendHeaders.addListener(make_ua_spoofer(UA_WINDOWS_CHROME),
                                                   {urls: fbFilterCatchAll},
                                                   ['blocking', 'requestHeaders'],
                                                  );
        break;
    case Browser.edge:
        browser.webRequest.onBeforeSendHeaders.addListener(
            make_ua_spoofer(UA_WINDOWS_CHROME, ['https://www.facebook.com/checkpoint/?next']),
            { urls: fbFilterCatchAll },
            ['blocking', 'requestHeaders'],
        );
        browser.webRequest.onBeforeSendHeaders.addListener(
            make_ua_spoofer(UA_WINDOWS_CHROME, null),
            { urls: fbFilterSpecific },
            ['blocking', 'requestHeaders'],
        );
        break;
}

client.then((c) => { c.onChange = sendStates.bind(null, c); });

switch (detectBrowser()) {
    case Browser.safari:
        //  https://stackoverflow.com/questions/9868985/safari-extension-first-run-and-updates
        const storedVersion = safari.extension.settings.version;
        const currentVersion = safari.extension.displayVersion + '.' + safari.extension.bundleVersion;
        if (typeof storedVersion === 'undefined') {
            //  Install
            safari.extension.settings.version = currentVersion;
            safari.extension.toolbarItems[0].showPopover();
        } else if (currentVersion !== storedVersion) {
            //  Update
            console.info('Extension update');
            safari.extension.settings.version = currentVersion;
        }
        break;
    default:
        chrome.runtime.onInstalled.addListener(function(details) {
            if (details.reason === 'install') {
                chrome.tabs.create({ url: '/popup.html' });
            } else if (details.reason === 'update') {
                const thisVersion = chrome.runtime.getManifest().version;
                console.info('Updated from ' + details.previousVersion + ' to ' + thisVersion);
            }
        });
        break;
}
