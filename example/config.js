function Config() {
	return {
		'ssid' : 'your ssid',
		"password" : "your p@$$vv0rD",
		"security" : "WPA2-ASK",

		get: function(key) {
			return this[key];
		}
	}
}

module.exports = new Config();
