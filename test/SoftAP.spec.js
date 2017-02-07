
require('should');

const SoftAP = require('../lib/SoftAP.js');


describe('softap', function() {

	it('can be constructed with options undefined', function() {
		var sut = new SoftAP();
		var defaults = SoftAP.defaultOptions();
		sut.should.have.property('host').be.eql(defaults.host);
		sut.should.have.property('keepAlive').be.eql(defaults.keepAlive);
	});


	it('can be constructed with options overridden', function() {
		var sut = new SoftAP({host:'abcd'});
		var defaults = SoftAP.defaultOptions();
		sut.should.have.property('host').be.eql('abcd');
		sut.should.have.property('keepAlive').be.eql(defaults.keepAlive);
	});

});