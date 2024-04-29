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
import { gdprDataHandler, gppDataHandler, uspDataHandler } from '../src/consentHandler.js';

/**
 * @typedef {import('../modules/userId/index.js').Submodule} Submodule
 * @typedef {import('../modules/userId/index.js').SubmoduleConfig} SubmoduleConfig
 * @typedef {import('../modules/userId/index.js').IdResponse} IdResponse
 */

const PCID_EXPIRY = 365;

const MODULE_NAME = 'intentIqId';
export const FIRST_PARTY_KEY = '_iiq_fdata';
export var FIRST_PARTY_DATA_KEY = '_iiq_fdata';
export var GROUP_LS_KEY = '_iiq_group';
export var WITH_IIQ = 'A';
export var WITHOUT_IIQ = 'B';
export var PERCENT_LS_KEY = '_iiq_percent';
export var DEFAULT_PERCENTAGE = 100;

export const storage = getStorageManager({ moduleType: MODULE_TYPE_UID, moduleName: MODULE_NAME });

const INVALID_ID = 'INVALID_ID';

/**
 * Generate random number between two numbers
 * @param start
 * @param end
 * @return {number}
 */
function getRandom(start, end) {
  return Math.floor(Math.random() * (end - start + 1) + start);
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
 * Remove Intent IQ data from cookie or local storage
 * @param key
 */
export function removeData(key) {
  try {
    if (storage.hasLocalStorage()) {
      storage.removeDataFromLocalStorage(key);
    }
    if (storage.cookiesAreEnabled()) {
      const expiredDate = new Date(0).toUTCString();
      storage.setCookie(key, '', expiredDate, 'LAX');
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

/**
 * Convert GPP data to an object
 * @param data
 * @param {string}
 */
function handleGPPData(data = {}) {
  if (Array.isArray(data)) {
      let obj = {};
      for (const element of data) {
          obj = Object.assign(obj, element);
      }
      return JSON.stringify(obj);
  }
  return JSON.stringify(data);
};

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

    // Get consent information
    const cmpData = {};
    const uspData = uspDataHandler.getConsentData();
    const gdprData = gdprDataHandler.getConsentData();
    const gppData = gppDataHandler.getConsentData();
    let isOptOut = false;

    if (uspData) {
      cmpData.us_privacy = uspData;
    }
  
    if (gdprData) {
      cmpData.gdpr = Number(Boolean(gdprData.gdprApplies));
      cmpData.gdpr_consent = gdprData.consentString || '';
      isOptOut = true;
    }
  
    if (gppData) {
      cmpData.gpp = '';

      if(gppData.parsedSections && 'usnat' in gppData.parsedSections) {
        cmpData.gpp = handleGPPData(gppData.parsedSections['usnat']);
      }
      cmpData.gpp_sid = gppData.applicableSections;
    }

    const cookieStorageEnabled = typeof configParams.enableCookieStorage === 'boolean' ? configParams.enableCookieStorage : false;
    let rrttStrtTime = 0;
    let partnerData = {};
    
    // If no GDPR, proceed as normal, remove any existing storage otherwise
    if(!isOptOut) {
      // Handle A/B testing
      if (isNaN(configParams.percentage)) {
        logInfo(MODULE_NAME + ' AB Testing percentage is not defined. Setting default value = ' + DEFAULT_PERCENTAGE);
        configParams.percentage = DEFAULT_PERCENTAGE;
      }

      if (isNaN(configParams.percentage) || configParams.percentage < 0 || configParams.percentage > 100) {
        logError(MODULE_NAME + 'Percentage - intentIqId submodule requires a valid percentage value');
        return false;
      }

      configParams.group = readData(GROUP_LS_KEY + '_' + configParams.partner);
      let percentage = readData(PERCENT_LS_KEY + '_' + configParams.partner);

      if (!configParams.group || !percentage || isNaN(percentage) || percentage != configParams.percentage) {
        logInfo(MODULE_NAME + 'Generating new Group. Current test group: ' + configParams.group + ', current percentage: ' + percentage + ' , configured percentage: ' + configParams.percentage);

        if (configParams.percentage > getRandom(1, 100)) { configParams.group = WITH_IIQ; } else configParams.group = WITHOUT_IIQ;

        storeData(GROUP_LS_KEY + '_' + configParams.partner, configParams.group)
        storeData(PERCENT_LS_KEY + '_' + configParams.partner, configParams.percentage + '')
        logInfo(MODULE_NAME + 'New group: ' + configParams.group)
      }

      if (configParams.group == WITHOUT_IIQ) {
        logInfo(MODULE_NAME + 'Group "B". Passive Mode ON.');
        return true;
      }

      if (!FIRST_PARTY_DATA_KEY.includes(configParams.partner)) { 
        FIRST_PARTY_DATA_KEY += '_' + configParams.partner; 
      }

      // Read Intent IQ 1st party id or generate it if none exists
      let firstPartyData = tryParse(readData(FIRST_PARTY_KEY));

      if (!firstPartyData || !firstPartyData.pcid || firstPartyData.pcidDate) {
        const firstPartyId = generateGUID();
        firstPartyData = { 'pcid': firstPartyId, 'pcidDate': Date.now() };

        storeData(FIRST_PARTY_KEY, JSON.stringify(firstPartyData), cookieStorageEnabled);
      }

      let storedPartnerData = tryParse(readData(FIRST_PARTY_DATA_KEY));

      if(storedPartnerData) partnerData = storedPartnerData;
    } else {
      removeData(FIRST_PARTY_KEY);
    }

    // use protocol relative urls for http or https
    let url = `https://api.intentiq.com/profiles_engine/ProfilesEngineServlet?at=39&mi=10&dpi=${configParams.partner}&pt=17&dpn=1`;
    url += configParams.pcid ? '&pcid=' + encodeURIComponent(configParams.pcid) : '';
    url += configParams.pai ? '&pai=' + encodeURIComponent(configParams.pai) : '';
    url += firstPartyData.pcid ? '&iiqidtype=2&iiqpcid=' + encodeURIComponent(firstPartyData.pcid) : '';
    url += firstPartyData.pid ? '&pid=' + encodeURIComponent(firstPartyData.pid) : '';
    url += partnerData.cttl ? '&cttl=' + encodeURIComponent(partnerData.cttl) : '';
    url += partnerData.rrtt ? '&rrtt=' + encodeURIComponent(partnerData.rrtt) : '';
    url += firstPartyData.pcidDate ? '&iiqpciddate=' + encodeURIComponent(firstPartyData.pcidDate) : '';
    url += cmpData.us_privacy ? '&us_privacy=' + encodeURIComponent(cmpData.us_privacy) : '';
    url += cmpData.gdpr ? '&gdpr=' + encodeURIComponent(cmpData.gdpr) : '';
    url += cmpData.gdpr_consent ? '&gdpr_consent=' + encodeURIComponent(cmpData.gdpr_consent) : '';
    url += cmpData.gpp ? '&gpv=' + encodeURIComponent(cmpData.gpp) : '';
    url += cmpData.gpp_sid ? '&gpp_sid=' + encodeURIComponent(cmpData.gpp_sid) : '';

    const resp = function (callback) {
      const callbacks = {
        success: response => {
          let respJson = tryParse(response);
          // If response is a valid json and should save is true
          if (respJson && respJson.ls) {
            // Store pid field if found in response json
            let shouldUpdateLs = false;
            if ('isOptOut' in respJson && respJson.isOptOut !== isOptOut) {
              isOptOut = respJson.isOptOut;
              firstPartyData.pid = respJson.pid;
              shouldUpdateLs = true;
            }
            if ('pid' in respJson) {
              firstPartyData.pid = respJson.pid;
              shouldUpdateLs = true;
            }
            if ('cttl' in respJson) {
              partnerData.cttl = respJson.cttl;
              shouldUpdateLs = true;
            }
            if ('eidl' in respJson) {
              partnerData.eidl = respJson.eidl;
            }
            // If should save and data is empty, means we should save as INVALID_ID
            if (respJson.data == '') {
              respJson.data = INVALID_ID;
            } else {
              partnerData.data = respJson.data;
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
