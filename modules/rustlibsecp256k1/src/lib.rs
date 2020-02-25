use secp256k1::curve::*;

#[no_mangle]
pub extern "C" fn RustProcess(
    coordx: &mut [u8; 32],
    coordy: &mut [u8; 32],
    scalar: &mut [u8; 32],
    result: &mut [u8; 65],
) -> u32 {
    let mut rx = Field::from_int(0);
    let _ = rx.set_b32(coordx);
    let mut ry = Field::from_int(0);
    let _ = ry.set_b32(coordy);
    let mut sc = Scalar::from_int(0);
    let _ = sc.set_b32(scalar);
    if sc.is_zero() {
        result[0] = 0;
        return 0;
    }
    let mut pt = Affine::default();
    pt.set_xy(&rx, &ry);
    let mut jac = Jacobian::default();
    ECMULT_CONTEXT.ecmult_const(&mut jac, &pt, &sc);
    pt.set_gej(&jac);
    pt.x.normalize();
    pt.y.normalize();

    let rsx = pt.x.b32();
    let rsy = pt.y.b32();
    result[0] = 0x04;
    for i in 0..32 {
        result[i + 1] = rsx[i]
    }
    for i in 0..32 {
        result[i + 33] = rsy[i]
    }

    return 0;
}
