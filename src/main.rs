use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::Fp256;
use ark_ff::QuadExtField;
use ark_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use ark_std::boxed::Box;
use ark_std::string::String;
use ark_std::string::ToString;
use ark_std::vec;
use ark_std::vec::Vec;
use codec::{Decode, Encode};
use ethabi::ParamType;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::{H256, U256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircomProof {
    #[serde(rename = "pi_a")]
    pub pi_a: Vec<String>,
    #[serde(rename = "pi_b")]
    pub pi_b: Vec<Vec<String>>,
    #[serde(rename = "pi_c")]
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

impl CircomProof {
    pub fn new(a: Vec<String>, b: Vec<Vec<String>>, c: Vec<String>) -> Self {
        CircomProof {
            pi_a: a,
            pi_b: b,
            pi_c: c,
            protocol: "groth16".to_string(),
            curve: "bn128".to_string(),
        }
    }

    pub fn to_proof(self) -> Proof<Bn254> {
        let a = G1Affine::new(
            Fp256::from_str(&self.pi_a[0]).unwrap(),
            Fp256::from_str(&self.pi_a[1]).unwrap(),
            false,
        );
        let b = G2Affine::new(
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[0][0]).unwrap(),
                Fp256::from_str(&self.pi_b[0][1]).unwrap(),
            ),
            QuadExtField::new(
                Fp256::from_str(&self.pi_b[1][0]).unwrap(),
                Fp256::from_str(&self.pi_b[1][1]).unwrap(),
            ),
            false,
        );

        let c = G1Affine::new(
            Fp256::from_str(&self.pi_c[0]).unwrap(),
            Fp256::from_str(&self.pi_c[1]).unwrap(),
            false,
        );
        Proof { a, b, c }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSignals(pub Vec<String>);

impl PublicSignals {
    pub fn from(public_signals: Vec<String>) -> Self {
        PublicSignals(public_signals)
    }

    pub fn get(self) -> Vec<Fr> {
        let mut inputs: Vec<Fr> = Vec::new();
        for input in self.0 {
            inputs.push(Fr::from_str(&input).unwrap());
        }
        inputs
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TypeInfo)]
pub enum VerificationError {
    InvalidProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TypeInfo)]
pub struct Verifier {
    pub vk_json: VerifyingKeyJson,
}

#[derive(Debug)]
pub enum VKeyDeserializationError {
    SerdeError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TypeInfo)]
pub struct VerifyingKeyJson {
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,

    #[serde(rename = "nPublic")]
    pub inputs_count: u32,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    pub curve: String,
    pub protocol: String,
}

impl VerifyingKeyJson {
    pub fn to_verifying_key(self) -> VerifyingKey<Bn254> {
        let alpha_g1 = G1Affine::from(G1Projective::new(
            str_to_fq(&self.vk_alpha_1[0]),
            str_to_fq(&self.vk_alpha_1[1]),
            str_to_fq(&self.vk_alpha_1[2]),
        ));
        let beta_g2 = G2Affine::from(G2Projective::new(
            // x
            Fq2::new(
                str_to_fq(&self.vk_beta_2[0][0]),
                str_to_fq(&self.vk_beta_2[0][1]),
            ),
            // y
            Fq2::new(
                str_to_fq(&self.vk_beta_2[1][0]),
                str_to_fq(&self.vk_beta_2[1][1]),
            ),
            // z,
            Fq2::new(
                str_to_fq(&self.vk_beta_2[2][0]),
                str_to_fq(&self.vk_beta_2[2][1]),
            ),
        ));

        let gamma_g2 = G2Affine::from(G2Projective::new(
            // x
            Fq2::new(
                str_to_fq(&self.vk_gamma_2[0][0]),
                str_to_fq(&self.vk_gamma_2[0][1]),
            ),
            // y
            Fq2::new(
                str_to_fq(&self.vk_gamma_2[1][0]),
                str_to_fq(&self.vk_gamma_2[1][1]),
            ),
            // z,
            Fq2::new(
                str_to_fq(&self.vk_gamma_2[2][0]),
                str_to_fq(&self.vk_gamma_2[2][1]),
            ),
        ));

        let delta_g2 = G2Affine::from(G2Projective::new(
            // x
            Fq2::new(
                str_to_fq(&self.vk_delta_2[0][0]),
                str_to_fq(&self.vk_delta_2[0][1]),
            ),
            // y
            Fq2::new(
                str_to_fq(&self.vk_delta_2[1][0]),
                str_to_fq(&self.vk_delta_2[1][1]),
            ),
            // z,
            Fq2::new(
                str_to_fq(&self.vk_delta_2[2][0]),
                str_to_fq(&self.vk_delta_2[2][1]),
            ),
        ));

        let gamma_abc_g1: Vec<G1Affine> = self
            .ic
            .iter()
            .map(|coords| {
                G1Affine::from(G1Projective::new(
                    str_to_fq(&coords[0]),
                    str_to_fq(&coords[1]),
                    str_to_fq(&coords[2]),
                ))
            })
            .collect();

        VerifyingKey::<Bn254> {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        }
    }
}

pub fn str_to_fq(s: &str) -> Fq {
    Fq::from_str(s).unwrap()
}

impl Verifier {
    /// Creates `Verifier` from json representation
    pub fn from_json_u8_slice(slice: &[u8]) -> Result<Self, VKeyDeserializationError> {
        serde_json::from_slice(slice).map_err(|_| VKeyDeserializationError::SerdeError)
    }

    // Verifies input based on the supplied proof and hashes
    pub fn verify(
        self,
        input_hash: H256,
        output_hash: H256,
        proof: Vec<u8>,
    ) -> Result<bool, VerificationError> {
        // remove first 3 bits from input_hash and output_hash
        let bits_mask = 0b00011111;
        let mut input_swap = input_hash.to_fixed_bytes();
        let input_hash_byte_swap = input_hash[0] & bits_mask;
        input_swap[0] = input_hash_byte_swap;

        let mut output_swap = output_hash.to_fixed_bytes();
        let output_hash_byte_swap = output_hash[0] & bits_mask;
        output_swap[0] = output_hash_byte_swap;

        let mut decoded: (Vec<String>, Vec<Vec<String>>, Vec<String>) = decode_proof(proof);
        decoded.1[0].reverse();
        decoded.1[1].reverse();
        // TODO remove printlns
        // println!("decoded proof: {:?}", decoded);

        let circom_proof = CircomProof::new(decoded.0, decoded.1, decoded.2);
        let proof = circom_proof.to_proof();

        let mut input = vec!["0".to_string(); 2];
        input[0] = U256::from_big_endian(output_swap.as_slice()).to_string();
        input[1] = U256::from_big_endian(input_swap.as_slice()).to_string();

        let public_signals = PublicSignals::from(input);

        // println!("public signals: {:?}", public_signals);

        let result = self.verify_proof(proof.clone(), &public_signals.get());

        result.map_err(|_| VerificationError::InvalidProof)
    }
    fn verify_proof(self, proof: Proof<Bn254>, inputs: &[Fr]) -> Result<bool, VerificationError> {
        let vk = self.vk_json.to_verifying_key();
        let pvk = prepare_verifying_key(&vk);

        let result = verify_proof(&pvk, &proof, inputs);
        result.map_err(|_| VerificationError::InvalidProof)
    }
}

pub fn decode_proof(proof: Vec<u8>) -> (Vec<String>, Vec<Vec<String>>, Vec<String>) {
    let decoded = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2),
            ParamType::FixedArray(
                Box::new(ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2)),
                2,
            ),
            ParamType::FixedArray(Box::new(ParamType::Uint(256)), 2),
        ])],
        &proof,
    )
    .expect("Proof must be decodable .qed");

    let mut a0: String = String::new();
    let mut a1: String = String::new();

    let mut b00: String = String::new();
    let mut b01: String = String::new();
    let mut b10: String = String::new();
    let mut b11: String = String::new();

    let mut c0: String = String::new();
    let mut c1: String = String::new();

    if let Some(ethabi::Token::Tuple(t)) = decoded.get(0) {
        if let ethabi::Token::FixedArray(ar) = &t[0] {
            if let ethabi::Token::Uint(u) = &ar[0] {
                a0 = u.to_string();
            }
            if let ethabi::Token::Uint(u) = &ar[1] {
                a1 = u.to_string();
            }
        }

        if let ethabi::Token::FixedArray(ar) = &t[1] {
            if let ethabi::Token::FixedArray(arr) = &ar[0] {
                if let ethabi::Token::Uint(u) = &arr[0] {
                    b00 = u.to_string();
                }
                if let ethabi::Token::Uint(u) = &arr[1] {
                    b01 = u.to_string();
                }
            }

            if let ethabi::Token::FixedArray(ar) = &t[1] {
                if let ethabi::Token::FixedArray(arr) = &ar[1] {
                    if let ethabi::Token::Uint(u) = &arr[0] {
                        b10 = u.to_string();
                    }
                    if let ethabi::Token::Uint(u) = &arr[1] {
                        b11 = u.to_string();
                    }
                }
            }
        }

        if let ethabi::Token::FixedArray(ar) = &t[2] {
            if let ethabi::Token::Uint(u) = &ar[0] {
                c0 = u.to_string();
            }
            if let ethabi::Token::Uint(u) = &ar[1] {
                c1 = u.to_string();
            }
        }
    }

    (
        vec![a0, a1],
        vec![vec![b00, b01], vec![b10, b11]],
        vec![c0, c1],
    )
}

// implements abi.encodePacked
pub fn encode_packed(poseidon: U256, slot: u64) -> Vec<u8> {
    let bytes: &mut [u8; 32] = &mut [0u8; 32];
    poseidon.to_big_endian(bytes);
    let slot_bytes = slot.to_be_bytes();
    let mut result = bytes.to_vec();
    result.extend_from_slice(slot_bytes.as_slice());
    result
}

fn main() {}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sp_core::{H256, U256};
    use sp_io::hashing::sha2_256;

    use super::*;

    #[test]
    fn test_zk_step_with_serde() {
        let vk = r#"{"vk_json":{
			"protocol": "groth16",
			"curve": "bn128",
			"nPublic": 2,
			"vk_alpha_1": [
			 "20491192805390485299153009773594534940189261866228447918068658471970481763042",
			 "9383485363053290200918347156157836566562967994039712273449902621266178545958",
			 "1"
			],
			"vk_beta_2": [
			 [
			  "6375614351688725206403948262868962793625744043794305715222011528459656738731",
			  "4252822878758300859123897981450591353533073413197771768651442665752259397132"
			 ],
			 [
			  "10505242626370262277552901082094356697409835680220590971873171140371331206856",
			  "21847035105528745403288232691147584728191162732299865338377159692350059136679"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_gamma_2": [
			 [
			  "10857046999023057135944570762232829481370756359578518086990519993285655852781",
			  "11559732032986387107991004021392285783925812861821192530917403151452391805634"
			 ],
			 [
			  "8495653923123431417604973247489272438418190587263600148770280649306958101930",
			  "4082367875863433681332203403145435568316851327593401208105741076214120093531"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_delta_2": [
			 [
			  "677302577815076814357170457144294271294364985082280272249076505900964830740",
			  "5628948730667472013190771331033856457010306836153142947462627646651446565415"
			 ],
			 [
			  "5877290568297658003612857476419103064356778304319760331670835003648166891449",
			  "10874997846396459971354014654692242947705540424071616448481145872912634110727"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_alphabeta_12": [],
			"IC": [
			 [
			  "202333273032481017331373350816007583026713320195536354260471885571526195724",
			  "8246242704115088390751476790768744984402990892657920674334938931948100192840",
			  "1"
			 ],
			 [
			  "12901454334783146822957332552289769626984444933652541503990843020723194328882",
			  "12436078488518552293095332739673622487901350475115357313978341690183990059269",
			  "1"
			 ],
			 [
			  "12828056956769114977702246128118682473179646035440405756936949778100648490262",
			  "7351319165217643779735289066901404053730163225836026220896225559268517203790",
			  "1"
			 ]
			]
		   }}"#;

        let v = Verifier::from_json_u8_slice(vk.as_bytes()).unwrap();

        assert_eq!("bn128", v.vk_json.curve);
        assert_eq!("groth16", v.vk_json.protocol);

        // Proof: https://alpha.succinct.xyz/explorer/49593376-e615-448a-9500-9985c0b478d5 (12/20)
        let inp = hex!(
            "0dbc986427113812b5c602296c4111534468b85b8ab478a9e75d9cd172d520cc00000000007a6b62"
        );
        let out = hex!("333045fa94a521a8eb3fed94d20b84d0fb0ebd8f65aa235586cadc7c5e91949e3119e018f159333ff6dc4600c912a148c0763a5195908a695389e211bad8a7a400000000007a6b2001ff");
        let inp_hash = H256(sha2_256(inp.as_slice()));
        let out_hash = H256(sha2_256(out.as_slice()));

        let proof = hex!("167232bcfa85aa66bee622d21b1917e5b7d5c5521f77b2064c39f009623391fa0f11ed9a6033eac0a293bc7bba55464825acbd1f0abe6235646b9da51e9aaea70a2c227b00a77fff5783905743674178cb64df8700e37963a42bd60116cdebb413be0718acdd215ce5f92d5b243d1af9855ed666f5090ce0d06de70e1c649f2c12fde213ae2598a47e2ca0dbc273b66aae32257010b9592b836e8592745a2087122ce0e6eda5d168ade0c12a12dae7dcd1b87ccaa82638fc4a215d440d3b3c1204a3cea09a8021870375863b2e3498ca88426826eb8089ca37fd1fc8273b4b1e16507d91fbbf7c486651cc214684e728c607009fd41e252b301c0628a1fc393f");

        let result = v.verify(inp_hash, out_hash, proof.to_vec());

        assert_eq!(true, result.unwrap());
    }

    #[test]
    fn test_zk_rotate_with_serde() {
        let vk = r#"{"vk_json":{
			"protocol": "groth16",
			"curve": "bn128",
			"nPublic": 2,
			"vk_alpha_1": [
			 "20491192805390485299153009773594534940189261866228447918068658471970481763042",
			 "9383485363053290200918347156157836566562967994039712273449902621266178545958",
			 "1"
			],
			"vk_beta_2": [
			 [
			  "6375614351688725206403948262868962793625744043794305715222011528459656738731",
			  "4252822878758300859123897981450591353533073413197771768651442665752259397132"
			 ],
			 [
			  "10505242626370262277552901082094356697409835680220590971873171140371331206856",
			  "21847035105528745403288232691147584728191162732299865338377159692350059136679"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_gamma_2": [
			 [
			  "10857046999023057135944570762232829481370756359578518086990519993285655852781",
			  "11559732032986387107991004021392285783925812861821192530917403151452391805634"
			 ],
			 [
			  "8495653923123431417604973247489272438418190587263600148770280649306958101930",
			  "4082367875863433681332203403145435568316851327593401208105741076214120093531"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_delta_2": [
			 [
			  "2864156988502350018268114524769442611229738724281856064310359811414088775164",
			  "19784911050814990253005325251017779746002278450060367709911093357779852409724"
			 ],
			 [
			  "2320747355788118605608963241136772405889379999161258135797985959373766905799",
			  "7118041328407665643077665093375077236507031390654037220453830314560753892708"
			 ],
			 [
			  "1",
			  "0"
			 ]
			],
			"vk_alphabeta_12": [],
			"IC": [
			 [
			  "15615341388138779177592192310982411536626378440854127969627902314302018589756",
			  "15825561397777957655855081872509949298182852212017977148985160662370122761845",
			  "1"
			 ],
			 [
			  "21866659777455953012076240694890418723891531368136637553921599064988704009798",
			  "18794682133425820197214508210971026410261369883290190279860606526851568182754",
			  "1"
			 ],
			 [
			  "17134706853007662603932468543386586959990776778768283640697616786730646170163",
			  "20580957029031123131958004810864543174606183854578157485523871304119815226629",
			  "1"
			 ]
			]
		   }}"#;

        let v = Verifier::from_json_u8_slice(vk.as_bytes()).unwrap();

        assert_eq!("bn128", v.vk_json.curve);
        assert_eq!("groth16", v.vk_json.protocol);
        // Proof: https://alpha.succinct.xyz/explorer/34970e06-f00d-4237-af22-8b5b81b7370a (12/19)
        let inp = hex!("f7eab670473c807c714456ffbc111dbef64804436b134b31ed1069cf96b4c737");
        let out = hex!("0d45c87ac168b1824eaabe6176f1138870d3f5a4bcaf80933c106b48fe7af194");
        let inp_hash = H256(sha2_256(inp.as_slice()));
        let out_hash = H256(sha2_256(out.as_slice()));

        let proof = hex!("1c28476628bca422f398cb181bae32ed6a3a4c47e19753c53cc060d6907e1df62459571d33a066464ec8fba36fef74b376bd4ac51333fd65c3a21d5f40fef3be0e3a397c7795a5a4806b42bd00fbe75e74fc0c996a6d77ab956ac641cd13645a2a0c666e8af9c8ac323316257e1165053ef7324bc9a47d3716ece2405d07c9441318b436a49d37be962205eb3ef870c69c30f152564f7713a7b198f6bbdcc5d00ffb8ea21b677646d26a009bccbebd2f67b13f4876403e795619f1f784d0dc8806e3bcc3594253630b3a4f55e150b7a78ba26ed2162fe7e3fd65a99e591cf8b700cf8c4621bd2892a1bf0644271f14e77e0b02ff3ec34e17d9183cfae8668ce6");

        let result = v.verify(inp_hash, out_hash, proof.to_vec());

        assert_eq!(true, result.unwrap());
    }

    #[test]
    fn test_decode_proof() {
        let proof = hex!("1332c772a8f9a02f304b5472d3b6b75f1a494bd9b137fc663fd5b9b475992bc829ba08f7cfa745e340938e356b139224d0288b9511a5cec83235f969f61a94ed16a14579fa0adcc3bf8da36209f64547fd5ff4e1c7e8b5b151335b5b4a471de3115f83b696517ac68ae7620f7d3840e44aff4781c0a4d265a2905ef9bcaa04432a660197790e60d1135946ae0603ef69a5ecb45b6f8046167f902dc6d8a35cf716bce116484dfa4fcd5d8f4c2fda26d68754b56e68f1a877d95dc171accc34d71285068693fe3d8d28e66342c31292ceee5c6d87fcb8ad8c132363565f2aeff905726b2d35def5c9636dd5ec402d8d6f6c9a7be7977e7e5727da327ea5b079ad");

        let decoded: (Vec<String>, Vec<Vec<String>>, Vec<String>) = decode_proof(proof.to_vec());

        assert_eq!(
            "8683663015073067038244847214283351810649000192281314413199884219842452597704",
            decoded.0[0]
        );
        assert_eq!(
            "18873522240908759015197166908776808810045074443031598381394130502027574940909",
            decoded.0[1]
        );
        assert_eq!(
            "10235824555245197129038838261179705064387070473723531210466639418098968894947",
            decoded.1[0][0]
        );
        assert_eq!(
            "7858077948381560609212308446029826533408997041182829878371843519718814778435",
            decoded.1[0][1]
        );
        assert_eq!(
            "19177369026551579179894492468331397687405155911290633487631565284771023248631",
            decoded.1[1][0]
        );
        assert_eq!(
            "10284603410671614550643238877116026784009997646397200180055169244522533893335",
            decoded.1[1][1]
        );
        assert_eq!(
            "8376666972810749572085581968561346381911579868801081275529626269155085447161",
            decoded.2[0]
        );
        assert_eq!(
            "2463724514031046292864306191243943409912346551164607808423034641717054699949",
            decoded.2[1]
        );
    }

    #[test]
    fn test_input_hashing_encode_packed() {
        let requested_input = hex!(
            "0ab2afdc05c8b6ae1f2ab20874fb4159e25d5c1d4faa41aee232d6ab331332df0000000000747ffe"
        );
        let requested_input_hash = sha2_256(requested_input.as_slice());
        let stored_poseidon =
            U256::from("0ab2afdc05c8b6ae1f2ab20874fb4159e25d5c1d4faa41aee232d6ab331332df");
        let stored_slot = 7634942u64;
        let res = encode_packed(stored_poseidon, stored_slot);
        assert_eq!(
            sha2_256(requested_input.as_slice()),
            sha2_256(res.as_slice())
        )
    }
}
