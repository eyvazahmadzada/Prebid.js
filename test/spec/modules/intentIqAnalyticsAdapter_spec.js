import { expect } from 'chai';
import iiqAnalyticsAnalyticsAdapter from 'modules/intentIqAnalyticsAdapter.js';
// import * as utils from 'src/utils.js';
// import { server } from 'test/mocks/xhr.js';
// import adapterManager from 'src/adapterManager.js';
import { config } from 'src/config.js';
import { EVENTS } from 'src/constants.js';
import * as events from 'src/events.js';

const partner = 10;
const pai = '11';
const pcid = '12';
const userPercentage = 0;
const defaultPercentage = 100;
const defaultConfigParams = { params: { partner: partner } };
const percentageConfigParams = { params: { partner: partner, percentage: userPercentage } };
const paiConfigParams = { params: { partner: partner, pai: pai } };
const pcidConfigParams = { params: { partner: partner, pcid: pcid } };
const allConfigParams = { params: { partner: partner, pai: pai, pcid: pcid } };
const responseHeader = { 'Content-Type': 'application/json' }

const testData = { data: 'test' }

const FIRST_PARTY_DATA_KEY = '_iiq_fdata'
const PRECENT_LS_KEY = '_iiq_precent'
const GROUP_LS_KEY = '_iiq_group'
const WITH_IIQ = 'A'
const WITHOUT_IIQ = 'B'

const USERID_CONFIG = [
  {
    'name': 'intentIqId',
    'params': {
      'partner': partner,
      'unpack': null,
      'percentage': 100,
    },
    'storage': {
      'type': 'html5',
      'name': 'intentIqId',
      'expires': 60,
      'refreshInSeconds': 14400
    }
  }
]

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
  'status': 'rendered',
};

describe('IntentIQ tests all', function () {
  let ixhr;
  let requests = [];

  beforeEach(function () {
    sinon.stub(config, 'getConfig').withArgs('userSync.userIds').returns(USERID_CONFIG);
    ixhr = sinon.useFakeXMLHttpRequest();
    requests = [];
    ixhr.onCreate = (a) => {
      requests.push(a);
    };
    sinon.stub(events, 'getEvents').returns([]);
    iiqAnalyticsAnalyticsAdapter.enableAnalytics({
      provider: 'iiqAnalytics',
    });
    sinon.spy(iiqAnalyticsAnalyticsAdapter, 'track');
  });

  afterEach(function () {
    config.getConfig.restore();
    events.getEvents.restore();
    requests = [];
    ixhr.restore();
    iiqAnalyticsAnalyticsAdapter.disableAnalytics();
    iiqAnalyticsAnalyticsAdapter.track.restore();
  });

  describe('IntentIQ tests', function () {
    it('IIQ Analytical Adapter bid win report', function () {
      iiqAnalyticsAnalyticsAdapter.enableAnalytics({
        provider: 'iiqAnalytics'
      });

      localStorage.setItem(PRECENT_LS_KEY + '_' + partner, '95');
      localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'A');
      localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"f961ffb1-a0e1-4696-a9d2-a21d815bd344"}');

      events.emit(EVENTS.BID_WON, wonRequest);

      expect(requests[0].url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
      expect(requests[0].url).to.contain('&jsver=5.3&source=pbjs&payload=');
    });

    it('should initialize with default configurations', function () {
      iiqAnalyticsAnalyticsAdapter.enableAnalytics({
        provider: 'iiqAnalytics'
      });
      expect(iiqAnalyticsAnalyticsAdapter.initOptions.lsValueInitialized).to.be.false;
    });

    it('should handle BID_WON event with user percentage configuration', function () {
      iiqAnalyticsAnalyticsAdapter.enableAnalytics({
        provider: 'iiqAnalytics'
      });

      localStorage.setItem(PRECENT_LS_KEY + '_' + partner, '50');
      localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'B');
      localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"testpcid"}');

      events.emit(EVENTS.BID_WON, wonRequest);

      expect(requests[0].url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
      expect(requests[0].url).to.contain('&jsver=5.3&source=pbjs&payload=');
    });

    it('should handle BID_WON event with default percentage configuration', function () {
      iiqAnalyticsAnalyticsAdapter.enableAnalytics({
        provider: 'iiqAnalytics'
      });

      localStorage.setItem(PRECENT_LS_KEY + '_' + partner, '100');
      localStorage.setItem(GROUP_LS_KEY + '_' + partner, 'A');
      localStorage.setItem(FIRST_PARTY_DATA_KEY + '_' + partner, '{"pcid":"defaultpcid"}');

      events.emit(EVENTS.BID_WON, wonRequest);

      expect(requests[0].url).to.contain('https://reports.intentiq.com/report?pid=' + partner + '&mct=1&agid=');
      expect(requests[0].url).to.contain('&jsver=5.3&source=pbjs&payload=');
    });
  });
});
