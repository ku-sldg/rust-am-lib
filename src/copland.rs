#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::Result;
use base64::Engine;
use core::panic;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

type Plc = String;
type N_ID = String;
type ASP_ID = String;
type TARG_ID = String;
pub type ASP_ARGS = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ASP_PARAMS {
    ASP_ID: ASP_ID,
    ASP_ARGS: ASP_ARGS,
    ASP_PLC: Plc,
    ASP_TARG_ID: TARG_ID,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "FWD_CONSTRUCTOR", content = "FWD_BODY")]
enum FWD {
    COMP,
    ENCR,
    EXTD(String),
    KILL,
    KEEP,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "EVIDENCE_CONSTRUCTOR", content = "EVIDENCE_BODY")]
enum Evidence {
    mt,
    nn(N_ID),
    uu(Plc, FWD, ASP_PARAMS, Box<Evidence>),
    ss(Box<Evidence>, Box<Evidence>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum SP {
    ALL,
    NONE,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "ASP_CONSTRUCTOR", content = "ASP_BODY")]
enum ASP {
    NULL,
    CPY,
    ASPC(SP, FWD, ASP_PARAMS),
    SIG,
    HSH,
    ENC(Plc),
}

/*
impl Serialize for ASP {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
            match *self {
                ASP::NULL => serializer.serialize_unit_variant("ASP", 0, "NULL"),
                ASP::CPY =>  serializer.serialize_unit_variant("ASP", 1, "CPY"),
                _ => serializer.serialize_unit_variant("ASP", 0, "NULL")
            }
     }
    }


impl Deserialize for ASP {

}
*/

type Split = (SP, SP);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "TERM_CONSTRUCTOR", content = "TERM_BODY")]
enum Term {
    asp(ASP),
    att(Plc, Box<Term>),
    lseq(Box<Term>, Box<Term>),
    bseq(Split, Box<Term>, Box<Term>),
    bpar(Split, Box<Term>, Box<Term>),
}

//type BS = bytestring::ByteString;

type RawEvT = Vec<String>; //Vec<BS>;

pub type EvidenceT = Vec<Vec<u8>>;

#[derive(Serialize, Deserialize, Debug)]
//#[serde(untagged)]
//#[serde(tag = "RawEv_CONSTRUCTOR", content = "RawEv_BODY")]
enum RawEv {
    RawEv(RawEvT),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "AppResultC_CONSTRUCTOR", content = "AppResultC_BODY")]
enum AppResultC {
    mtc_app,
    nnc_app(N_ID, String),
    ggc_app(Plc, ASP_PARAMS, RawEv, Box<AppResultC>),
    hhc_app(Plc, ASP_PARAMS, String, Box<AppResultC>),
    eecc_app(Plc, ASP_PARAMS, String, Box<AppResultC>),
    ssc_app(Box<AppResultC>, Box<AppResultC>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Attestation_Session {
    Session_Plc: Plc,
    Plc_Mapping: HashMap<Plc, String>,
    PubKey_Mapping: HashMap<Plc, String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProtocolRunRequest {
    TYPE: String,
    ACTION: String,
    REQ_PLC: Plc,
    TERM: Term,
    RAWEV: RawEv,
    ATTESTATION_SESSION: Attestation_Session,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProtocolRunResponse {
    TYPE: String,
    ACTION: String,
    SUCCESS: bool,
    PAYLOAD: RawEv,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProtocolAppraiseRequest {
    TYPE: String,
    ACTION: String,
    ATTESTATION_SESSION: Attestation_Session,
    TERM: Term,
    REQ_PLC: Plc,
    EVIDENCE: Evidence,
    RAWEV: RawEv,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProtocolAppraiseResponse {
    TYPE: String,
    ACTION: String,
    SUCCESS: bool,
    PAYLOAD: AppResultC,
}

#[derive(Serialize, Deserialize, Debug)]
struct ASPRunRequest {
    TYPE: String,
    ACTION: String,
    ASP_ID: String,
    ASP_ARGS: ASP_ARGS,
    ASP_PLC: Plc,
    ASP_TARG_ID: TARG_ID,
    RAWEV: RawEv,
}

#[derive(Serialize, Deserialize, Debug)]
struct ASPRunResponse {
    TYPE: String,
    ACTION: String,
    SUCCESS: bool,
    PAYLOAD: RawEv,
}

fn successfulASPRunResponse(evidence: RawEv) -> ASPRunResponse {
    ASPRunResponse {
        TYPE: "RESPONSE".to_string(),
        ACTION: "ASP_RUN".to_string(),
        SUCCESS: true,
        PAYLOAD: evidence,
    }
}

// Currently the reason string is ignored, but eventually
// should be incorporated into the response.
fn failureASPRunResponse(_reason: String) -> ASPRunResponse {
    eprintln!("Error: {_reason}");

    ASPRunResponse {
        TYPE: "RESPONSE".to_string(),
        ACTION: "ASP_RUN".to_string(),
        SUCCESS: false,
        PAYLOAD: RawEv::RawEv(Vec::new()),
    }
}

// NOTE: This function will exit the process with a status code of 1
fn respond_with_failure(reason: String) -> ! {
    let resp_json = serde_json::to_string(&failureASPRunResponse(reason)).unwrap_or_else(|error| {
        panic!("Failed to json.encode failure response: {error:?}");
    });
    println!("{resp_json}");
    std::process::exit(1);
}

// Convert base64 encoded string to vec u8
fn base64_to_vec(base64: &str) -> Vec<u8> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .unwrap_or_else(|error| {
            respond_with_failure(format!("Failed to decode base64: {error:?}"));
        });
    bytes
}

fn vec_to_base64(vec: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(vec)
}

fn rawev_to_vec(rawev: RawEv) -> Vec<Vec<u8>> {
    match rawev {
        RawEv::RawEv(rawevt) => rawevt.iter().map(|base64| base64_to_vec(&base64)).collect(),
    }
}

fn vec_to_rawev(vec: Vec<Vec<u8>>) -> RawEv {
    RawEv::RawEv(vec.iter().map(|bytes| vec_to_base64(bytes)).collect())
}

pub fn handle_body(body: fn(EvidenceT, ASP_ARGS) -> Result<EvidenceT>) -> ! {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ASPRunRequest JSON>", args[0]);
        respond_with_failure("Invalid arguments to ASP".to_string());
    }

    let json_req = &args[1];
    let req: ASPRunRequest = serde_json::from_str(json_req).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ASPRunRequest: {error:?}"));
    });
    match body(rawev_to_vec(req.RAWEV), req.ASP_ARGS) {
        Ok(ev) => {
            let response = successfulASPRunResponse(vec_to_rawev(ev));
            let resp_json = serde_json::to_string(&response).unwrap_or_else(|error| {
                respond_with_failure(format!("Failed to json.encode response: {error:?}"));
            });
            println!("{resp_json}");
            std::process::exit(0);
        }
        Err(reason) => {
            respond_with_failure(reason.to_string());
        }
    }
}
