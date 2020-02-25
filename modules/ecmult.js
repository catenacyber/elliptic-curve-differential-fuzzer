//var ec = new EC(process.argv[2]);
var pt1 = ec.curve.decodePoint(inputPoint, "hex")
var sc = utils.toArray(inputScalar, "hex")
var pt2 = pt1.mul(sc)
r = pt2.encode('hex')
//console.log(r);
