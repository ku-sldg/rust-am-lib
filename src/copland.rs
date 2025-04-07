#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::Result;
use base64::Engine;
use core::panic;
use serde::{Deserialize, Serialize};
use serde_json::{Value};
use std::collections::HashMap;

pub type Plc = String;
type N_ID = String;
type ASP_ID = String;
type TARG_ID = String;
pub type ASP_ARGS = serde_json::Value;

static APPRAISAL_SUCCESS_RESPONSE: &str = "";

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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "EvInSig_CONSTRUCTOR", content = "EvInSig_BODY")]
enum EvInSig {
    InAll,
    InNone
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "EvOutSig_CONSTRUCTOR", content = "EvOutSig_BODY")]
enum EvOutSig {
    OutN(String),
    OutUnwrap
}

#[derive(Serialize, Deserialize, Debug)]
struct EvSig {
    FWD: FWD,
    EvInSig: EvInSig,
    EvOutSig: EvOutSig
}

type ASP_Type_Env = HashMap<ASP_ID, EvSig>;
type ASP_Compat_MapT = HashMap<ASP_ID, ASP_ID>;

#[derive(Serialize, Deserialize, Debug)]
struct GlobalContext {
    asp_types: ASP_Type_Env,
    asp_comps: ASP_Compat_MapT
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "EVIDENCET_CONSTRUCTOR", content = "EVIDENCET_BODY")]
enum EvidenceT {
    mt_evt,
    nonce_evt(N_ID),
    asp_evt(Plc, ASP_PARAMS, Box<EvidenceT>),
    left_evt(Box<EvidenceT>),
    right_evt(Box<EvidenceT>),
    split_evt(Box<EvidenceT>, Box<EvidenceT>)
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

pub type ASP_RawEv = Vec<Vec<u8>>;

#[derive(Serialize, Deserialize, Debug)]
//#[serde(untagged)]
//#[serde(tag = "RawEv_CONSTRUCTOR", content = "RawEv_BODY")]
pub enum RawEv {
    RawEv(RawEvT),
}

#[derive(Serialize, Deserialize, Debug)]
struct Evidence {
    RawEv: RawEv,
    EvidenceT: EvidenceT
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Attestation_Session {
    Session_Plc: Plc,
    Plc_Mapping: HashMap<Plc, String>,
    PubKey_Mapping: HashMap<Plc, String>,
    ats_context: GlobalContext
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolRunRequest {
    TYPE: String,
    ACTION: String,
    REQ_PLC: Plc,
    TERM: Term,
    EVIDENCE: Evidence,
    ATTESTATION_SESSION: Attestation_Session,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolRunResponse {
    TYPE: String,
    ACTION: String,
    SUCCESS: bool,
    PAYLOAD: Evidence,
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

fn gather_args_and_req() -> (ASP_RawEv, ASP_ARGS) {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ASPRunRequest JSON>", args[0]);
        respond_with_failure("Invalid arguments to ASP".to_string());
    }

    let json_req = &args[1];
    let req: ASPRunRequest = serde_json::from_str(json_req).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ASPRunRequest: {error:?}"));
    });

    (rawev_to_vec(req.RAWEV), req.ASP_ARGS)
}

pub fn handle_appraisal_body(body: fn(ASP_RawEv, ASP_ARGS) -> Result<Result<()>>) -> ! {
    let (ev, args) = gather_args_and_req();
    match body(ev, args) {
        Ok(appr_res) => match appr_res {
            Ok(_) => {
                let response =
                    successfulASPRunResponse(RawEv::RawEv(vec![APPRAISAL_SUCCESS_RESPONSE.into()]));
                let resp_json = serde_json::to_string(&response).unwrap_or_else(|error| {
                    respond_with_failure(format!("Failed to json.encode response: {error:?}"));
                });
                println!("{resp_json}");
                std::process::exit(0);
            }
            Err(reason) => {
                // This is not a FAILURE, but rather an APPRAISAL that ended in a negative result.
                let response = successfulASPRunResponse(RawEv::RawEv(vec![reason.to_string()]));
                let resp_json = serde_json::to_string(&response).unwrap_or_else(|error| {
                    respond_with_failure(format!("Failed to json.encode response: {error:?}"));
                });
                println!("{resp_json}");
                std::process::exit(0);
            }
        },
        Err(reason) => {
            respond_with_failure(reason.to_string());
        }
    }
}

pub fn handle_body(body: fn(ASP_RawEv, ASP_ARGS) -> Result<ASP_RawEv>) -> ! {
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
