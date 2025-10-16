'use strict';
require('should');
const SoftAP = require('../lib/SoftAP.js');
const sinon = require('sinon');
const chai = require('chai');
const sinonChai = require('sinon-chai');
chai.use(sinonChai);
const expect = chai.expect;


describe('softap', function() {
	describe('constructor', function() {
		it('can be constructed with options undefined', function() {
			const sut = new SoftAP();
			const defaults = SoftAP.defaultOptions();
			sut.should.have.property('host').be.eql(defaults.host);
			sut.should.have.property('keepAlive').be.eql(defaults.keepAlive);
		});

		it('can be constructed with options overridden', function() {
			const sut = new SoftAP({ host:'abcd' });
			const defaults = SoftAP.defaultOptions();
			sut.should.have.property('host').be.eql('abcd');
			sut.should.have.property('keepAlive').be.eql(defaults.keepAlive);
		});
	});

	describe('deviceInfo', function() {
		it('converts the deviceID to lowercase', function() {
			const sut = new SoftAP();
			sut.__sendCommand = sinon.spy(function(command, cb) {
				cb(undefined, { id:'ABCD', c:'1' });
			});

			const cb = sinon.stub();
			sut.deviceInfo(cb);
			expect(cb).to.have.been.calledWith(null, { id:'abcd', claimed:true });
		});
	});
});
