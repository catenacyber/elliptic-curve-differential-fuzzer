var EC = require('elliptic').ec;
var utils = require('elliptic').utils;

var ec = new EC(process.argv[2]);
var pt1 = ec.curve.decodePoint(process.argv[3], "hex")
var sc = utils.toArray(process.argv[4], "hex")
var pt2 = pt1.mul(sc)
r = pt2.encode('hex')
console.log(r);
