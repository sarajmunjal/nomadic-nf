var redis = require("redis"),
client = redis.createClient('redis://35.185.112.146');
console.log("Connected to redis");
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