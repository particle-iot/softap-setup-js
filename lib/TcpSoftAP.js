'use strict';

var SoftAP = require('./SoftAP');
var util = require('util');
var net = require('net');

function TcpSoftAP(options) {
	SoftAP.call(this, options);
}
util.inherits(TcpSoftAP, SoftAP);

TcpSoftAP.prototype._sendProtocolCommand = function _sendProtocolCommand(cmd, cb) {
	var err, json;

	var sock = net.createConnection(this.port, this.host);
	sock.setNoDelay(this.noDelay);
	sock.setTimeout(this.timeout);
	sock.setKeepAlive(this.keepAlive);

	var to = setTimeout(function socketTimedOut() {
		err = new Error('TCP socket timed out');
		sock.destroy();
	}, this.timeout);

	sock.once('connect', function socketConnected() {
		var send;
		if (cmd.body && typeof cmd.body === 'object') {
			var body = JSON.stringify(cmd.body);
			var length = body.length;
			send = util.format('%s\n%s\n\n%s', cmd.name, length, body);
		} else {
			send = util.format('%s\n0\n\n', cmd.name);
		}

		sock.write(send);
	});

	sock.once('data', function socketData(dat) {
		clearTimeout(to);
		if (dat instanceof Buffer || typeof dat === 'string') {
			try {
				json = JSON.parse(dat.toString());
			} catch (e) {
				return cb(new Error('Invalid JSON received from device.'));
			}
		} else if (typeof dat === 'object') {
			json = dat;
		}

		sock.end();
	});

	sock.once('error', function socketError(error) {
		err = error;
		clearTimeout(to);
	});

	sock.once('timeout', function socketTimeout() {
		clearTimeout(to);
		err = new Error('TCP socket timed out');
		sock.destroy();
	});

	sock.once('close', function socketClose(hadError) {
		if (!err && hadError) {
			err = new Error('unknown socket error');
		}
		cb(err, json);
	});
};

module.exports = TcpSoftAP;
