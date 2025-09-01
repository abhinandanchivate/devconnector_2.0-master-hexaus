process.env.NODE_CONFIG = JSON.stringify({ jwtSecret: 'testsecret' });

const { test, mock } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const auth = require('./auth');

function createRes() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    }
  };
}

test('returns 401 if no token provided', () => {
  const req = { header: () => undefined };
  const res = createRes();
  const next = mock.fn();
  auth(req, res, next);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { msg: 'No token, authorization denied' });
  assert.equal(next.mock.callCount(), 0);
});

test('returns 401 if token invalid', () => {
  const req = { header: () => 'badtoken' };
  const res = createRes();
  const next = mock.fn();
  mock.method(jwt, 'verify', (token, secret, cb) => cb(new Error('bad')));
  auth(req, res, next);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { msg: 'Token is not valid' });
  assert.equal(next.mock.callCount(), 0);
  mock.restoreAll();
});

test('calls next and attaches user for valid token', () => {
  const payload = { user: { id: '123' } };
  const token = 'goodtoken';
  const req = { header: () => token };
  const res = createRes();
  const next = mock.fn();
  mock.method(jwt, 'verify', (tok, secret, cb) => cb(null, payload));
  auth(req, res, next);
  assert.deepEqual(req.user, payload.user);
  assert.equal(next.mock.callCount(), 1);
  assert.equal(res.statusCode, null);
  mock.restoreAll();
});
