module.exports = SoftAPSetup;

var config = require('./config');
var defaults = require('./config/defaults');
var softap = require('./softap');

function SoftAPSetup(opts) {

	if(opts && typeof opts == 'object') {
		Object.keys(opts).forEach(function _loadOpts(key) {
			config.set(key, opts[key]);
		});
	}

	var opts = {};
	opts.protocol = config.get('protocol');
	opts.keepAlive = config.get('keep_alive');
	opts.noDelay = config.get('no_delay');
	opts.timeout = config.get('timeout');

	opts.host = config.get('host');
	opts.port = config.get('port');

	if(!opts.protocol) {
		opts.protocol = config.get('default_protocol');
	}
	if(!opts.port) {
		opts.port = defaults.available_protocols[opts.protocol].port;
	}

	return new softap(opts);
};
