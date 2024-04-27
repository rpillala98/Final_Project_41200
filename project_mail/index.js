const { Mailsending } = require('./1.js');
const { WriteToBigQuery } = require('./2.js');

exports.Main = (message, context) => {
    Mailsending(message, context);
    WriteToBigQuery(message, context);
}
