use rand_core::{OsRng, SeedableRng};
use bip32::{Mnemonic, XPrv, ExtendedPrivateKey, secp256k1::ecdsa::SigningKey};
use rsa::{RsaPrivateKey};
use rand_chacha::ChaCha8Rng;
//Other instructions
use rsa::pkcs8::{EncodePrivateKey,LineEnding};
fn main() {
    let mnemo = get_mnemonic("post focus sail learn artwork sketch fade bridge debris doctor labor labor denial verb arm recycle clever attend share bulb vivid clown table lens").expect("The mnemonic is invalid");
    let bip_xprv = generate_bip_private_key(mnemo);
    let rsa_priv_key = generate_rsa_private_key(bip_xprv);
    let str_rsa_priv_key = rsa_priv_key.to_pkcs8_pem(LineEnding::default()).unwrap().to_string();

    println!("The generated private key is \"{}\"", str_rsa_priv_key);
}

// Other instructions

fn generate_mnemonic() -> Mnemonic {
    let mnemonic = Mnemonic::random(&mut OsRng, Default::default());
    mnemonic
}

fn get_mnemonic(phrase : &str) -> Result<Mnemonic,String> {
    return match Mnemonic::new(phrase, Default::default()){
        Ok(mnemo) => Ok(mnemo),
        Err(e) => Err(e.to_string())
    };
}


fn generate_bip_private_key(mnemo : Mnemonic) -> XPrv {
    let seed = mnemo.to_seed("");
    XPrv::new(&seed).unwrap()
}


fn generate_rsa_private_key(xprv : ExtendedPrivateKey<SigningKey>) -> RsaPrivateKey {
    let priv_attrs = xprv.attrs();
    let chain_code : [u8; 32] = priv_attrs.chain_code;

    let mut seed = ChaCha8Rng::from_seed(chain_code);
    RsaPrivateKey::new(&mut seed, 256).unwrap()
}