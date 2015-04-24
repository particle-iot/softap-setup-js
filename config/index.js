var nconf = require('nconf');

var config = nconf.file({
	file: 'defaults.json',
	dir: __dirname,
	search: true
}).env().argv();

Object.keys(config.get()).filter(function (key) {
	return !!key.match(/^SOFTAP_.*$/)
}).forEach(function (key) {
	config.set(key.replace('SOFTAP_', '').toLowerCase(), config.get(key))
})

module.exports = config;
