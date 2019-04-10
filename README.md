# pq-peer
Post Quantum Peer
This library will encrypt you connection with double aes 256 cbc encryption.
Key exchange are done trough newhope and x25519 cryptography.

Server to accept such peer
```javascript
const pqp = require("pq-peer");
const net = require("net");
const port = 9001;
net.createServer((sock)=>{
pqp.Server(sock,(peer,err)=>{
if(!err){
peer.on("data",(data)=>{
console.log("server received",data.toString());
peer.write(data);
});
}else console.log(err.message,err.code);
});
}).listen(port,"127.0.0.1");

```
Client example
```javascript
const pqp = require("pq-peer");
const net = require("net");
const port = 9001;
const host = "127.0.0.1";
var sock = new net.Socket();
sock.connect(9001, '127.0.0.1', function() {
pqp.Client(sock,(peer,err)=>{
if(!err){
peer.on("data",(data)=>{
console.log("client received",data.toString());

});
peer.write("hello");
}else console.log(err.message,err.code);
});
});
```
