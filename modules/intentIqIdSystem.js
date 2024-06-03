/**
 * This module adds IntentIqId to the User ID module
 * The {@link module:modules/userId} module is required
 * @module modules/intentIqIdSystem
 * @requires module:modules/userId
 */

import { logError, logInfo } from '../src/utils.js';
import { ajax } from '../src/ajax.js';
import { submodule } from '../src/hook.js'
import { getStorageManager } from '../src/storageManager.js';
import { MODULE_TYPE_UID } from '../src/activities/modules.js';

/**
 * @typedef {import('../modules/userId/index.js').Submodule} Submodule
 * @typedef {import('../modules/userId/index.js').SubmoduleConfig} SubmoduleConfig
 * @typedef {import('../modules/userId/index.js').IdResponse} IdResponse
 */

const PCID_EXPIRY = 365;

const MODULE_NAME = 'intentIqId';
export const FIRST_PARTY_KEY = '_iiq_fdata';
export var FIRST_PARTY_DATA_KEY = '_iiq_fdata';

export const storage = getStorageManager({ moduleType: MODULE_TYPE_UID, moduleName: MODULE_NAME });

const INVALID_ID = 'INVALID_ID';

let sessionKey = null;

/**
 * Generate a session key if it doesn't exist and store it in a runtime variable.
 * @returns {Promise<CryptoKey>} The generated CryptoKey.
 */
async function initializeSessionKey() {
  if (!sessionKey) {
    sessionKey = await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
  }
  return sessionKey;
}

/**
 * Encrypts plaintext using the session key.
 * @param {string} plainText The plaintext to encrypt.
 * @returns {Promise<string>} The encrypted text as a base64 string.
 */
async function encryptData(plainText) {
  const key = await initializeSessionKey();
  const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector (12 bytes)
  const enc = new TextEncoder();
  const encoded = enc.encode(plainText);

  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoded
  );

  const encryptedData = {
    iv: Array.from(iv),
    encrypted: Array.from(new Uint8Array(encrypted))
  };

  return btoa(JSON.stringify(encryptedData));
}

/**
 * Decrypts ciphertext using the session key.
 * @param {string} encryptedText The encrypted text as a base64 string.
 * @returns {Promise<string>} The decrypted plaintext.
 */
async function decryptData(encryptedText) {
  const key = await initializeSessionKey();
  const encryptedData = JSON.parse(atob(encryptedText));
  const iv = new Uint8Array(encryptedData.iv);
  const data = new Uint8Array(encryptedData.encrypted);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

/**
 * Generate standard UUID string
 * @return {string}
 */
function generateGUID() {
  let d = new Date().getTime();
  const guid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (d + Math.random() * 16) % 16 | 0;
    d = Math.floor(d / 16);
    return (c == 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
  return guid;
}

/**
 * Read Intent IQ data from cookie or local storage
 * @param key
 * @return {string}
 */
export function readData(key) {
  try {
    if (storage.hasLocalStorage()) {
      return storage.getDataFromLocalStorage(key);
    }
    if (storage.cookiesAreEnabled()) {
      return storage.getCookie(key);
    }
  } catch (error) {
    logError(error);
  }
}

/**
 * Store Intent IQ data in either cookie or local storage
 * expiration date: 365 days
 * @param key
 * @param {string} value IntentIQ ID value to sintentIqIdSystem_spec.jstore
 */
function storeData(key, value, cookieStorageEnabled = false) {
  try {
    logInfo(MODULE_NAME + ': storing data: key=' + key + ' value=' + value);

    if (value) {
      if (storage.hasLocalStorage()) {
        storage.setDataInLocalStorage(key, value);
      }
      const expiresStr = (new Date(Date.now() + (PCID_EXPIRY * (60 * 60 * 24 * 1000)))).toUTCString();
      if (storage.cookiesAreEnabled() && cookieStorageEnabled) {
        storage.setCookie(key, value, expiresStr, 'LAX');
      }
    }
  } catch (error) {
    logError(error);
  }
}

/**
 * Parse json if possible, else return null
 * @param data
 * @param {object|null}
 */
function tryParse(data) {
  try {
    return JSON.parse(data);
  } catch (err) {
    logError(err);
    return null;
  }
}

/** @type {Submodule} */
export const intentIqIdSubmodule = {
  /**
   * used to link submodule with config
   * @type {string}
   */
  name: MODULE_NAME,
  /**
   * decode the stored id value for passing to bid requests
   * @function
   * @param {{string}} value
   * @returns {{intentIqId: {string}}|undefined}
   */
  decode(value) {
    return value && value != '' && INVALID_ID != value ? { 'intentIqId': value } : undefined;
  },
  /**
   * performs action to obtain id and return a value in the callback's response argument
   * @function
   * @param {SubmoduleConfig} [config]
   * @returns {IdResponse|undefined}
   */
  getId(config) {
    const configParams = (config && config.params) || {};
    if (!configParams || typeof configParams.partner !== 'number') {
      logError('User ID - intentIqId submodule requires a valid partner to be defined');
      return;
    }
    const cookieStorageEnabled = typeof configParams.enableCookieStorage === 'boolean' ? configParams.enableCookieStorage : false
    if (!FIRST_PARTY_DATA_KEY.includes(configParams.partner)) { FIRST_PARTY_DATA_KEY += '_' + configParams.partner; }
    let rrttStrtTime = 0;

    // Read Intent IQ 1st party id or generate it if none exists
    let firstPartyData = tryParse(readData(FIRST_PARTY_KEY));
    if (!firstPartyData || !firstPartyData.pcid || firstPartyData.pcidDate) {
      const firstPartyId = generateGUID();
      firstPartyData = { 'pcid': firstPartyId, 'pcidDate': Date.now() };
      storeData(FIRST_PARTY_KEY, JSON.stringify(firstPartyData), cookieStorageEnabled);
    }

    let partnerData = tryParse(readData(FIRST_PARTY_DATA_KEY));

    if (partnerData.data) {
      console.log(decryptData(partnerData.data));
    }

    if (!partnerData) partnerData = {};

    // use protocol relative urls for http or https
    let url = `https://api.intentiq.com/profiles_engine/ProfilesEngineServlet?at=39&mi=10&dpi=${configParams.partner}&pt=17&dpn=1`;
    url += configParams.pcid ? '&pcid=' + encodeURIComponent(configParams.pcid) : '';
    url += configParams.pai ? '&pai=' + encodeURIComponent(configParams.pai) : '';
    url += firstPartyData.pcid ? '&iiqidtype=2&iiqpcid=' + encodeURIComponent(firstPartyData.pcid) : '';
    url += firstPartyData.pid ? '&pid=' + encodeURIComponent(firstPartyData.pid) : '';
    url += (partnerData.cttl) ? '&cttl=' + encodeURIComponent(partnerData.cttl) : '';
    url += (partnerData.rrtt) ? '&rrtt=' + encodeURIComponent(partnerData.rrtt) : '';
    url += firstPartyData.pcidDate ? '&iiqpciddate=' + encodeURIComponent(firstPartyData.pcidDate) : '';

    const resp = function (callback) {
      const callbacks = {
        success: response => {
          let respJson = tryParse(response);
          // If response is a valid json and should save is true
          if (respJson && respJson.ls) {
            // Store pid field if found in response json
            let shouldUpdateLs = false;
            if ('pid' in respJson) {
              firstPartyData.pid = respJson.pid;
              shouldUpdateLs = true;
            }
            if ('cttl' in respJson) {
              partnerData.cttl = respJson.cttl;
              shouldUpdateLs = true;
            }
            // If should save and data is empty, means we should save as INVALID_ID
            if (respJson.data == '') {
              respJson.data = INVALID_ID;
            } else {
              partnerData.data = encryptData(JSON.stringify(respJson.data));
              shouldUpdateLs = true;
            }
            if (rrttStrtTime && rrttStrtTime > 0) {
              partnerData.rrtt = Date.now() - rrttStrtTime;
              shouldUpdateLs = true;
            }
            if (shouldUpdateLs === true) {
              partnerData.date = Date.now();
              storeData(FIRST_PARTY_KEY, JSON.stringify(firstPartyData), cookieStorageEnabled);
              storeData(FIRST_PARTY_DATA_KEY, JSON.stringify(partnerData), cookieStorageEnabled);
            }
            callback(respJson.data);
          } else {
            callback();
          }
        },
        error: error => {
          logError(MODULE_NAME + ': ID fetch encountered an error', error);
          callback();
        }
      };
      if (partnerData.date && partnerData.cttl && partnerData.data &&
        Date.now() - partnerData.date < partnerData.cttl) { callback(partnerData.data); } else {
        rrttStrtTime = Date.now();
        ajax(url, callbacks, undefined, { method: 'GET', withCredentials: true });
      }
    };
    return { callback: resp };
  },
  eids: {
    'intentIqId': {
      source: 'intentiq.com',
      atype: 1
    },
  }
};

submodule('userId', intentIqIdSubmodule);
