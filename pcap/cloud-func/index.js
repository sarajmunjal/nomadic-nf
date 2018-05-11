var redis = require("redis"),
client = redis.createClient(5262, '35.224.66.131');
console.log("Connected to redis");
/*
exports.pktCtr = (req, res) => {
    var key = req.query.sessionName;
    console.log("Request to incr: " + key);
    if (!key) {
        res.status(500).send("Missing sessionName key!");
        return;
    }
    console.log("incr: " + key);
    client.incr(key, function (err, reply) {
        if (err) {
            console.log("Key: " + key + " err: " + err);
            res.status(500).send(err);
            return;
        }
        console.log("fin incr: " + key + " rep: " + reply);
        res.send('OK!');
    });
    console.log("wait: " + key);
};
*/

function store_packet_signature(pkt){
    
    key   = pkt['tx_id']+'--'+pkt['q_url'];

    //return value;
    console.log("Key: " + key);
    console.log("Pkt: " + pkt);

    client.set(key, JSON.stringify(pkt), function (err, res) { return res});
}

/*
const express = require('express');
const app = express();
*/

exports.dnsdetect = (req, res) => {
    pkt = req.body;
    tx_id = pkt['tx_id'];
    q_url = pkt['q_url'];
    key = tx_id+'--'+q_url;
    op = JSON.parse(client.get(key));
    if (op.dst == pkt['dst']){
        if (op.sport == pkt['sport']){
            if (op.dport == pkt['dport']){
                if (op.rdata != pkt['rdata']){
                    if (op.tx_id == pkt['tx_id']){
                        if (op.DNS.q_url == pkt['q_url']){
                            /*print(str(datetime.datetime.now())+ "  DNS poisoning attempt")
                            print("TXID %s Request URL %s"%( op[DNS].id, op[DNS].qd.qname.decode('utf-8').rstrip('.')))
                            print("Answer1 [%s]"%op[DNSRR].rdata)
                            print("Answer2 [%s]"%packet[DNSRR].rdata)
                            */
                            store_packet_signature(pkt);
                            res.send("DNS Poisoning Detected");
                        }
                    }
                }
             }
        }
    }

    value = store_packet_signature(pkt);

    res.send('Latest Test : '+ JSON.stringify(op));
};

exports.receive_tcp_flow = (req, res) => {
    
    flow = req.body;
    flow_size = 0
    flow.forEach(function(packet) {
        
        flow_size += parseInt(packet.size);
        
    });

    res.send("Flow size: " + flow_size);
};

exports.receive_dns_flow = (req, res) => {
    

    
};


//app.listen(8000);
