var net = require('net');

var args = process.argv;
var from_port = parseInt(args[2]);
var to_port = parseInt(args[3]);
var target = net.connect(to_port, function() {
    var requests = [];
    var reply = '';
    var replyN = null;
    var server = net.createServer(function(c) {
        var data = '';
        var n = null;
        c.setEncoding('binary');
        c.on('data', function(d) {
            data += d;
            if (n == null && data.length >= 4) {
                var buf = new Buffer(data.substring(0, 4), 'binary');
                n = buf.readUInt32LE(0);
            }
            if (n != null && data.length == n + 4) {
                requests.push(function(answer) {
                    c.write(answer, 'binary');
                });
                target.write(data, 'binary');
            }
        });

    });
    target.setEncoding('binary');
    target.on('data', function(d) {
        reply += d;
        if (replyN == null && reply.length >= 4) {
            var buf = new Buffer(reply.substring(0, 4), 'binary');
            replyN = buf.readUInt32LE(0);
        }
        if (replyN!= null && reply.length >= replyN + 4) {
            var answer = reply.substring(0, replyN + 4);
            reply = reply.substring(replyN + 4);
            requests[0](answer);
            requests.splice(0, 1);
            replyN = null;
            if (replyN == null && reply.length >= 4) {
                var buf = new Buffer(reply.substring(0, 4), 'binary');
                replyN = buf.readUInt32LE(0);
            }
        }
    });

    server.listen(from_port, function() {
      console.log('server ready');
    });
});

