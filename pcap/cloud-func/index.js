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
    
    dst   = pkt.IP.dst;
    sport = pkt.UDP.sport;
    dport = pkt.UDP.dport;
    tx_id = pkt.DNS.id;
    q_url = pkt.DNS.qd['DNS Question Record'].qname;

    rdata = pkt['DNS Resource Record'].rdata;
    key   = tx_id+'--'+q_url;

    value = {
            'dst'  : dst,
            'sport': sport,
            'dport': dport,
            'tx_id': tx_id,
            'q_url': q_url,
            'rdata': rdata
        };

    
    //return value;

    client.set(key, JSON.stringify(value), function (err, res) { return res});
}

/*
const express = require('express');
const app = express();
*/

exports.dnsdetect = (req, res) => {
    pkt = req.body;
    tx_id = pkt.DNS.id;
    q_url = pkt.DNS.qd['DNS Question Record'].qname;
    key = tx_id+'--'+q_url;
    op = JSON.parse(client.get(key));
    if (op.dst == pkt.IP.dst){
        if (op.sport == pkt.UDP.sport){
            if (op.dport == pkt.UDP.dport){
                if (op.rdata != pkt['DNS Resource Record'].rdata){
                    if (op.tx_id == pkt.DNS.id){
                        if (op.DNS.q_url == pkt.DNS.qd['DNS Question Record'].qname){
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


//app.listen(8000);
