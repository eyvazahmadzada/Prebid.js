import { expect } from 'chai';
import iiqAnalyticsAnalyticsAdapter from 'modules/intentIqAnalyticsAdapter.js';
import * as utils from 'src/utils.js';
import { server } from 'test/mocks/xhr.js';
import { config } from 'src/config.js';
import { EVENTS } from 'src/constants.js';
import * as events from 'src/events.js';
import { getStorageManager } from 'src/storageManager.js';
import sinon from 'sinon';
import { FIRST_PARTY_KEY } from '../../../modules/intentIqIdSystem';

const partner = 10;
const pai = '11';
const pcid = '12';
const userPercentage = 0;
const defaultPercentage = 100;
const FIRST_PARTY_DATA_KEY = '_iiq_fdata';
const PERCENT_LS_KEY = '_iiq_percent';
const GROUP_LS_KEY = '_iiq_group';

const storage = getStorageManager({ moduleType: 'analytics', moduleName: 'iiqAnalytics' });

const USERID_CONFIG = [
  {
    'name': 'intentIqId',
    'params': {
      'partner': partner,
      'unpack': null,
      'percentage': defaultPercentage,
    },
    'storage': {
      'type': 'html5',
      'name': 'intentIqId',
      'expires': 60,
      'refreshInSeconds': 14400
    }
  }
];

let wonRequest = {
  'bidderCode': 'pubmatic',
  'width': 728,
  'height': 90,
  'statusMessage': 'Bid available',
  'adId': '23caeb34c55da51',
  'requestId': '87615b45ca4973',
  'transactionId': '5e69fd76-8c86-496a-85ce-41ae55787a50',
  'auctionId': '0cbd3a43-ff45-47b8-b002-16d3946b23bf',
  'mediaType': 'banner',
  'source': 'client',
  'cpm': 5,
  'currency': 'USD',
  'ttl': 300,
  'referrer': '',
  'adapterCode': 'pubmatic',
  'originalCpm': 5,
  'originalCurrency': 'USD',
  'responseTimestamp': 1669644710345,
  'requestTimestamp': 1669644710109,
  'bidder': 'testbidder',
  'adUnitCode': 'addUnitCode',
  'timeToRespond': 236,
  'pbLg': '5.00',
  'pbMg': '5.00',
  'pbHg': '5.00',
  'pbAg': '5.00',
  'pbDg': '5.00',
  'pbCg': '',
  'size': '728x90',
  'status': 'rendered'
};

describe('IntentIQ tests all', function () {
  let logErrorStub;

  beforeEach(function () {
    logErrorStub = sinon.stub(utils, 'logError');
    sinon.stub(config, 'getConfig').withArgs('userSync.userIds').returns(USERID_CONFIG);
    sinon.stub(events, 'getEvents').returns([]);
    iiqAnalyticsAnalyticsAdapter.enableAnalytics({
      provider: 'iiqAnalytics',
    });
    iiqAnalyticsAnalyticsAdapter.initOptions = {
      lsValueInitialized: false,
      partner: null,
      fpid: null,
      userGroup: null,
      userPercentage: null,
      currentGroup: null,
      currentPercentage: null,
      dataInLs: null,
      eidl: null,
      lsIdsInitialized: false,
      manualReport: false
    };
    if (iiqAnalyticsAnalyticsAdapter.track.restore) {
      iiqAnalyticsAnalyticsAdapter.track.restore();
    }
    sinon.spy(iiqAnalyticsAnalyticsAdapter, 'track');
  });

  afterEach(function () {
    logErrorStub.restore();
    config.getConfig.restore();
    events.getEvents.restore();
    iiqAnalyticsAnalyticsAdapter.disableAnalytics();
    if (iiqAnalyticsAnalyticsAdapter.track.restore) {
      iiqAnalyticsAnalyticsAdapter.track.restore();
    }
  });

  it('IIQ Analytical Adapter bid win report', function () {
    localStorage.setItem(PERCENT_LS_KEY + '_' + partner, defaultPercentage);
    localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'A');
    localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"f961ffb1-a0e1-4696-a9d2-a21d815bd344"}');

    events.emit(EVENTS.BID_WON, wonRequest);

    expect(server.requests.length).to.be.above(0);
    const request = server.requests[0];
    expect(request.url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
    expect(request.url).to.contain('&jsver=5.3&source=pbjs&payload=');
  });

  it('should initialize with default configurations', function () {
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.lsValueInitialized).to.be.false;
  });

  it('should handle BID_WON event with user percentage configuration', function () {
    localStorage.setItem(PERCENT_LS_KEY + '_' + partner, userPercentage);
    localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'B');
    localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"testpcid"}');

    events.emit(EVENTS.BID_WON, wonRequest);

    expect(server.requests.length).to.be.above(0);
    const request = server.requests[0];
    expect(request.url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
    expect(request.url).to.contain('&jsver=5.3&source=pbjs&payload=');
  });

  it('should handle BID_WON event with default percentage configuration', function () {
    localStorage.setItem(PERCENT_LS_KEY + '_' + partner, defaultPercentage);
    localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'A');
    localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"defaultpcid"}');

    events.emit(EVENTS.BID_WON, wonRequest);

    expect(server.requests.length).to.be.above(0);
    const request = server.requests[0];
    expect(request.url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
    expect(request.url).to.contain('&jsver=5.3&source=pbjs&payload=');
  });

  it('should not send request if manualReport is true', function () {
    iiqAnalyticsAnalyticsAdapter.initOptions.manualReport = true;
    events.emit(EVENTS.BID_WON, wonRequest);
    expect(server.requests.length).to.equal(0);
  });

  it('should read data from local storage', function () {
    localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"data":"testpcid", "eidl": 10}');
    events.emit(EVENTS.BID_WON, wonRequest);
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.dataInLs).to.equal('testpcid');
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.eidl).to.equal(10);
  });

  it('should handle initialization values from local storage', function () {
    localStorage.setItem(PERCENT_LS_KEY + '_' + partner, 50);
    localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'B');
    localStorage.setItem(FIRST_PARTY_KEY, '{"pcid":"testpcid"}');
    events.emit(EVENTS.BID_WON, wonRequest); // This will call initLsValues internally
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.currentGroup).to.equal('B');
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.currentPercentage).to.equal(50);
    expect(iiqAnalyticsAnalyticsAdapter.initOptions.fpid).to.be.not.null;
  });
});
