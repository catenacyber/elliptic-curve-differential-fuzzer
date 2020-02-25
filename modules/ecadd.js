//var ec = new EC(process.argv[2]);
var pt1 = ec.curve.decodePoint(inputPoint, "hex")
var pt2 = ec.curve.decodePoint(inputPoint2, "hex")
var pt3 = pt1.add(pt2)
r = pt3.encode('hex')
//console.log(r);
