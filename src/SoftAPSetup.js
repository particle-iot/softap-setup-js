import net from 'net';
import request from 'request';
import RSA from 'node-rsa';

const securityTable = {
  'open': 0,
  'none': 0,
  'wep_psk': 1,
  'wep_shared': 0x8001,
  'wpa_tkip': 0x00200002,
  'wpa_aes': 0x00200004,
  'wpa2_aes': 0x00400004,
  'wpa2_tkip': 0x00400002,
  'wpa2_mixed': 0x00400006,
  'wpa2': 0x00400006,
};

function parseRes(res) {
  if ( res instanceof Buffer || typeof res === 'string' ) {
    try {
      return JSON.parse(res.toString());
    } catch (e) {
      throw new Error(`Invalid JSON received in response: ${e}`);
    }
  } else if ( typeof res === 'object') {
    return res;
  }
  throw new Error('How did this even happen???');
}

export default class SoftAPSetup {
  constructor({
    protocol = 'tcp',
    keepAlive = true,
    noDelay = true,
    timeout = 2000,
    host = '192.168.0.1',
    port,
  } = {}) {
    this.protocol = protocol;
    this.keepAlive = keepAlive;
    this.noDelay = noDelay;
    this.timeout = timeout;
    this.host = host;
    // If port is specified, use it
    // If it's not, use 5609 if the protocol is tcp. else use 80
    if ( !port ) {
      this.port = protocol === 'tcp' ? '5609' : '80';
    } else {
      this.port = port;
    }
    this._publicKey = null;
  }

  scan() {
    return this._sendCommand('scan-ap');
  }

  connect() {
    return this._sendCommand({
      name: 'connect-ap',
      body: {
        idx: 0,
      },
    });
  }

  deviceInfo() {
    return this._sendCommand('device-id')
      .then((data) => {
        return {
          id: data.id,
          claimed: data.c === '1',
        };
      });
  }

  publicKey() {
    return this._sendCommand('public-key')
      .then((data) => {
        if ( !data ) {
          throw new Error('No data received');
        }
        const { r, b } = data;
        if ( r !== 0 ) {
          throw new Error('Received non-zero response code');
        }
        const buff = new Buffer(b, 'hex');
        this._publicKey = new RSA(
          buff.slice(22),
          'pkcs1-public-der', {
            encryptionScheme: 'pkcs1',
          }
        );
        return this._publicKey.exportKey('pkcs8-public');
      });
  }

  setClaimCode(code) {
    if ( typeof code !== 'string' ) {
      throw new Error('Code must be a string');
    }
    return this._sendCommand({
      name: 'set',
      body: { k: 'cc', v: code },
    });
  }

  configure({ security = 'open', channel = 6, ssid, password } = {}) {
    if ( !this._publicKey ) {
      throw new Error('Must retrieve public key prior to configuration');
    }
    if ( !ssid ) {
      throw new Error('Configuration options contain no ssid property');
    }
    let pwd;
    if ( password ) {
      pwd = this._publicKey.encrypt(password, 'hex');
    }

    const sec = securityTable[security];
    if ( sec === undefined ) {
      throw new Error('Invalid security type');
    }

    const ch = parseInt(channel, 10);
    if ( !ch ) {
      throw new Error('Invalid channel');
    }

    return this._sendCommand({
      name: 'configure-ap',
      body: { ssid, sec, pwd, ch, idx: 0 },
    });
  }

  version() {
    return this._sendCommand('version');
  }

  securityLookup(code) {
    return Object.keys(securityTable).find((key) => obj[key] === code);
  }

  _sendCommand(arg) {
    let name;
    let body;
    if ( typeof arg === 'string' ) {
      name = arg;
    } else {
      name = arg.name;
      body = arg.body;
    }
    if ( this.protocol === 'http' ) {
      return this._httpRequest(name, body);
    }
    return this._tcpMessage(name, body);
  }

  /**
   * Make an http request to the AP server
   *
   * @param {String} path - the path of the endpoint to call
   * @param {Object} data - if this is set, will make a POST request. Else
   *   using a GET request
   * @return {Promise}
   * @rejects {Error}
   * @resolves {Object} - the JSON format of the response
   */
  _httpRequest(path, data) {
    const url = `http://${this.host}:${this.port}/${path}`;
    if ( body ) {
      return new Promise((resolve, reject) => {
        request.post({
          url,
          body: data,
          json: true,
        }, (err, response, body) => {
          if (err) reject(err);
          else {
            try {
              resolve( parseRes(body) );
            } catch (e) {
              reject(e);
            }
          }
        });
      });
    }
    return new Promise((resolve, reject) => {
      request.get({ url }, (err, message, body) => {
        if (err) reject(err);
        else {
          try {
            resolve( parseRes(body) );
          } catch (e) {
            reject(e);
          }
        }
      });
    });
  }

  /**
   * Send a tcp message to the AP server
   * @param  {String} command - the name of the message
   * @param  {Object} data - any data you want to include
   * @return {Promise}
   * @rejects {Error} - any errors that may have happened
   * @resolves {Object} - the JSON format of the response
   */
  _tcpMessage(command, data) {
    const message = data ?
      `${command}\n${body.length}\n\n${JSON.stringify(data)}` :
      `${command}\n0\n\n`;

    const socket = net.createConnection(this.port, this.host);
    socket.setTimeout(this.timeout);
    socket.write(message);

    return new Promise((resolve, reject) => {
      socket.on('error', reject);
      socket.on('data', (res) => {
        try {
          resolve( parseRes(res) );
        } catch (e) {
          reject(e);
        }
      });
    });
  }

}
