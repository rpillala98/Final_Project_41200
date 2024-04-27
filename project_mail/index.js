const { Mailsending } = require('./1.js');
const { WriteToBigQuery } = require('./6.js');

exports.Main = (message, context) => {
    Mailsending(message, context);
    WriteToBigQuery(message, context);
}

