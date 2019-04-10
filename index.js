
var crypto = require("crypto");
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;
var newhope_1 = require("@stablelib/newhope");
var ed25519 = require("ed25519-ekpm");


class peer_error extends Error {
  constructor(message,code,stack) {
    super(message);
    this.message = message;
    this.name = 'peer-error';
    this.code = code;
    if(stack)
     this.stack = stack;
  }
}
const ErrorCodes = {
 unknown_error:0,
 callback_parameter_missing:1,
 handshake_invalid_size:2,
 handshake_server_initial_packet_invalid:3,
 unsupporeted_protocol_version:4,
 invalid_protocol_version:5,
 encryption_fail:6,
 decryption_fail:7,
 connection_error:8
};

var ErrorMessages = {};
ErrorMessages[ErrorCodes.encryption_fail] = "Encryption failed";
ErrorMessages[ErrorCodes.decryption_fail] = "Decryption failed";
ErrorMessages[ErrorCodes.handshake_invalid_size] = "Invalid handshake packet size";
ErrorMessages[ErrorCodes.invalid_protocol_version] = "Invalid protocol version";
ErrorMessages[ErrorCodes.unsupporeted_protocol_version] = "Unsupporeted protocol version";
ErrorMessages[ErrorCodes.handshake_server_initial_packet_invalid] = "Server sent invalid initial packet";
ErrorMessages[ErrorCodes.callback_parameter_missing] = "Callback parameter must be supplied";
module.exports.ErrorCodes = ErrorCodes;

function encryptDataWithKey(data,password){
var mykey = crypto.createCipher('aes-256-cbc', password);
var encrypted = mykey.update(data);
return Buffer.concat([encrypted, mykey.final()]);
}
function decryptDataWithKey(enc,password){
var mykey = crypto.createDecipher('aes-256-cbc',password);
var decrypted = mykey.update(enc)
return Buffer.concat([decrypted, mykey.final()]);
}
function pq_peer(sock,nhk,x5k,version){
 var self = this;
 EventEmitter.call(self);
 self._sock = sock; 
 self._nhk = nhk;
 self._x5k = x5k;
 sock.once("close",()=>{self.emit("close");});
 sock.once("error",(err)=>{
   self.emit("error",new peer_error(err.message,
				      ErrorCodes.connection_error,err.stack));
  });
 sock.on("data",(data)=>{
   try{
    data = decryptDataWithKey(decryptDataWithKey(data,self._nhk),self._x5k);
   }catch(e){
     self.emit("error",new peer_error(ErrorMessages[ErrorCodes.decryption_fail],
				      ErrorCodes.decryption_fail));
     sock.destroy();
     return;
   }
   self.emit("data",data);
  });
 self.write = (msg)=>{
   try{
   msg = encryptDataWithKey(encryptDataWithKey(msg,self._x5k),self._nhk);
   }catch(e){
      self.emit("error",new peer_error(ErrorMessages[ErrorCodes.encryption_fail],
				      ErrorCodes.encryption_fail));
      sock.destroy();
      return;
   }
   sock.write(msg);
 }
  self.destroy = ()=>{
   sock.destroy();
  };
 
}
inherits(pq_peer, EventEmitter);
function doVersion1AuthClient(sock,cb){
  var nh = new newhope_1.NewHope(undefined,crypto);
  var noffer = nh.offer();
  var msg = new Buffer(noffer.length+1);
  msg.writeInt8(1,0);
  Buffer(noffer).copy(msg,1,0,noffer.length);
  sock.write(msg);
  sock.once("data",(data)=>{
   if(data.length < newhope_1.ACCEPT_MESSAGE_LENGTH+1){
    sock.destroy();
    cb(null,new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size));
    return;
   }
   var acceptMsg = data.slice(1,newhope_1.ACCEPT_MESSAGE_LENGTH+1);
   nh.finish(acceptMsg);
   var nhKey = nh.getSharedKey();
   nh.clean();
   data = data.subarray(newhope_1.ACCEPT_MESSAGE_LENGTH+1);
   if(data.length < 32){
    sock.destroy();
    cb(null,new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size));
    return;
   }
   try{
   var data = decryptDataWithKey(data,nhKey);
   var x2 = ed25519.xKeyPairNew();
   var acceptMsg = x2.accept(data);
   var sharedKey = Buffer(x2.sharedKey);
   var buf = new Buffer(1);
   buf.writeInt8(1,0);
   buf = encryptDataWithKey(buf,sharedKey);
   var msg = new Buffer(acceptMsg.length+1+buf.length);
   msg.writeInt8(1,0);
   Buffer(acceptMsg).copy(msg,1,0,acceptMsg.length);
   buf.copy(msg,acceptMsg.length+1,0,buf.length);
   msg = encryptDataWithKey(msg,nhKey);
   sock.write(msg);
   sock.once("data",(data)=>{
     try{
    data = decryptDataWithKey(decryptDataWithKey(data,nhKey),sharedKey);
    if(data.readInt8(0) == 1){
    cb(new pq_peer(sock,nhKey,sharedKey),null);
    }else {
     throw new peer_error(ErrorMessages[ErrorCodes.invalid_protocol_version],
				      ErrorCodes.invalid_protocol_version); 
    }
     }catch(e){
       sock.destroy();
       if(!(e instanceof peer_error)){
	 e = new peer_error(e.message,
				      ErrorCodes.unknown_error,e.stack);
       }
       cb(null,e);
       return;
     }
  });
   }catch(e){
    sock.destroy();
    if(!(e instanceof peer_error)){
	 e = new peer_error(e.message,
				      ErrorCodes.unknown_error,e.stack);
       }
    cb(null,e);
    return;
   }
  });
}
function doVersion1AuthServer(sock,cb,data){  
if(data.length != newhope_1.OFFER_MESSAGE_LENGTH+1){
   throw new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size);
    return;
}
var offerMsg = data.slice(1,newhope_1.OFFER_MESSAGE_LENGTH+1);
var nh = new newhope_1.NewHope(undefined,crypto);
var acceptMsg = nh.accept(offerMsg);
var nhKey = nh.getSharedKey();
nh.clean();
var x2 = ed25519.xKeyPairNew();
var xoffer = x2.offer();
xoffer = encryptDataWithKey(xoffer,nhKey);
var msg = new Buffer(acceptMsg.length+1+xoffer.length);
msg.writeInt8(1,0);
Buffer(acceptMsg).copy(msg,1,0,acceptMsg.length);
Buffer(xoffer).copy(msg,1+acceptMsg.length,0,xoffer.length);
sock.write(msg);
sock.once("data",(data)=>{
  try{
    data = decryptDataWithKey(data,nhKey);
    if(data.length<1+ed25519.ACCEPT_MESSAGE_LENGTH){
     throw new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size);
     return;
    }
    var version = data.readInt8(0);
    if(version != 1){
     throw  new peer_error(ErrorMessages[ErrorCodes.invalid_protocol_version],
				      ErrorCodes.invalid_protocol_version);
     return;
    }
    var key = data.slice(1,ed25519.ACCEPT_MESSAGE_LENGTH+1);
    x2.finish(key);
    var sharedKey = x2.sharedKey;
     data = data.slice(ed25519.ACCEPT_MESSAGE_LENGTH+1);
     data = decryptDataWithKey(data,sharedKey);
     var version = data.readInt8(0);
     if(version == 1){
       var msg = new Buffer(1);
       msg.writeInt8(1,0);
       msg = encryptDataWithKey(msg,sharedKey);
       msg = encryptDataWithKey(msg,nhKey);
       sock.write(msg);
       cb(new pq_peer(sock,nhKey,sharedKey),null);
     }else {
      throw new peer_error(ErrorMessages[ErrorCodes.unsupporeted_protocol_version],
				      ErrorCodes.unsupporeted_protocol_version); 
     }
  }catch(e){
   sock.destroy();
   if(!(e instanceof peer_error)){
	 e = new peer_error(e.message,
				      ErrorCodes.unknown_error,e.stack);
    }
   cb(null,e);
   return;
  }
});
}
var serverProtocols = [1];
module.exports.Client = (sock,version,cb)=>{
    
    if(typeof version == "function"){
     cb = version;
     version = 1;
    }
    if(typeof cb != "function"){
      sock.destroy();
      throw new peer_error(ErrorMessages[ErrorCodes.callback_parameter_missing],
				      ErrorCodes.callback_parameter_missing);
    }
    if(serverProtocols.indexOf(version) == -1){
      sock.destroy();
     throw new peer_error(ErrorMessages[ErrorCodes.unsupporeted_protocol_version],
				      ErrorCodes.unsupporeted_protocol_version);
    }
    sock.once("data",(data)=>{
      try{
      if(data.length<2){
	throw new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size)
	return;
      }
      if(data.readInt8(0) != 0){
	throw new peer_error(ErrorMessages[ErrorCodes.handshake_server_initial_packet_invalid],
				      ErrorCodes.handshake_server_initial_packet_invalid);
	return;
      }
      var protocol_length = data.readInt8(1);
      if(protocol_length == 0|| protocol_length*4+2>data.length){
	throw new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size)
	return;
      }
      for(var i=0;i<protocol_length;i++){
	var protocol_version = data.readInt32LE(i*4+2);
	if(version == protocol_version){
    switch(version){
     case 1:{
    doVersion1AuthClient(sock,cb);
    }
    break;
    }
	  return;
	}
      }
      throw new peer_error(ErrorMessages[ErrorCodes.unsupporeted_protocol_version],
				      ErrorCodes.unsupporeted_protocol_version);
	/// cb un supported protocol
    }catch(e){
     sock.destroy();
     if(!(e instanceof peer_error)){
	 e = new peer_error(e.message,
				      ErrorCodes.unknown_error,e.stack);
       }
     cb(null,e);
    }
    });
  };
  module.exports.Server = (sock,cb)=>{
  if(typeof cb != "function"){
      throw new peer_error(ErrorMessages[ErrorCodes.callback_parameter_missing],
				      ErrorCodes.callback_parameter_missing);
   }
  var msg = new Buffer(serverProtocols.length*4+2);
  msg.writeInt8(0,0);
  msg.writeInt8(serverProtocols.length,1);
  for(var i in serverProtocols){
   msg.writeInt32LE(serverProtocols[i],i*4+1+1); 
  }
  sock.write(msg);
  sock.once("data",(data)=>{
    try{
    var length = data.length;
    if(length < 1){
     throw new peer_error(ErrorMessages[ErrorCodes.handshake_invalid_size],
				      ErrorCodes.handshake_invalid_size);
     return;
    }
    var version = data.readInt8(0);
    switch(version){
      case 1:{
      doVersion1AuthServer(sock,cb,data);
    }
    break;
      default:
     throw  new peer_error(ErrorMessages[ErrorCodes.invalid_protocol_version],
				      ErrorCodes.invalid_protocol_version);
    }
    }catch(e){
      sock.destroy();
      if(!(e instanceof peer_error)){
	 e = new peer_error(e.message,
				      ErrorCodes.unknown_error,e.stack);
       }
     cb(null,e); 
    }
  });
  };