var repl = require('repl');
var config = require('./config');
var SoftAPSetup = require('./index');

var replServer = repl.start({
	useColors: true,
	prompt: "SoftAPSetup > "
});

replServer.context.config = config;
replServer.context.SoftAPSetup = SoftAPSetup;
