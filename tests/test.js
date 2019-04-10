 

 
const pqp = require("../");
const net = require("net");
const crypto = require("crypto");



net.createServer((sock)=>{
  console.log("server incomming connection");
  pqp.Server(sock,(peer,err)=>{
     console.log("server",err);
     if(!err){
      peer.on("data",(data)=>{
	console.log("server peer received "+data.toString());
	if(data.toString() == "hello to you my friend"){
	console.log("test passed");
	process.exit(0);
	}else {
	 console.log("test failed");
	 process.exit(1);
	}
      });
      peer.write("hello bro");
      peer.once("error",(err)=>{
	 console.log("test failed");
	 process.exit(1);
      });
     }else {
      console.log("test failed");
	 process.exit(1); 
     }
  });
  sock.once("close",()=>{
    
    console.log("server close");
  });
  
}).listen(9001,"127.0.0.1");



var client = new net.Socket();
client.connect(9001, '127.0.0.1', function() {
	console.log('Connected');
	pqp.Client(client,(peer,err)=>{
	console.log("client",err);
	if(!err){
	peer.on("data",(data)=>{
	console.log("client peer received "+data.toString());
	if(data.toString() != "hello bro"){
	 console.log("test failed");
	 process.exit(1);
	}
	peer.write("hello to you my friend");
	}); 
	peer.once("error",(err)=>{
	 console.log("test failed");
	 process.exit(1);
	});
	}else {
	 console.log("test failed");
	 process.exit(1); 
	}
	});
});

client.once("close",()=>{
  console.log("client close");
});