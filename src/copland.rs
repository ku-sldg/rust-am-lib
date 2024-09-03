#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub type Plc = String;
type N_ID = String;
pub type ASP_ID = String;
pub type TARG_ID = String;
pub type ASP_ARGS = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ASP_PARAMS {
    pub ASP_ID: ASP_ID,
    pub ASP_ARGS: ASP_ARGS,
    pub ASP_PLC: Plc,
    pub ASP_TARG_ID: TARG_ID
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "FWD_CONSTRUCTOR", content = "FWD_BODY")]
pub enum FWD {
    COMP,
    ENCR,
    EXTD(String),
    KILL,
    KEEP
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "EVIDENCE_CONSTRUCTOR", content = "EVIDENCE_BODY")]
pub enum Evidence {
    mt,
    nn(N_ID),
    uu(Plc, FWD, ASP_PARAMS, Box<Evidence>),
    ss(Box<Evidence>, Box<Evidence>)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SP {
    ALL,
    NONE
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "ASP_CONSTRUCTOR", content = "ASP_BODY")]
pub enum ASP {
    NULL,
    CPY,
    ASPC(SP, FWD, ASP_PARAMS),
    SIG,
    HSH,
    ENC(Plc)
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
pub enum Term {
    asp(ASP),
    att(Plc, Box<Term>),
    lseq(Box<Term>, Box<Term>),
    bseq(Split, Box<Term>, Box<Term>),
    bpar(Split, Box<Term>, Box<Term>)
}

//type BS = bytestring::ByteString;

type RawEvT = Vec<String>;  //Vec<BS>;

#[derive(Serialize, Deserialize, Debug)]
//#[serde(untagged)]
//#[serde(tag = "RawEv_CONSTRUCTOR", content = "RawEv_BODY")]
pub enum RawEv {
    RawEv(RawEvT)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "AppResultC_CONSTRUCTOR", content = "AppResultC_BODY")]
pub enum AppResultC {
    mtc_app,
    nnc_app(N_ID, String),
    ggc_app(Plc, ASP_PARAMS, RawEv, Box<AppResultC>),
    hhc_app(Plc, ASP_PARAMS, String, Box<AppResultC>),
    eecc_app(Plc, ASP_PARAMS, String, Box<AppResultC>),
    ssc_app(Box<AppResultC>, Box<AppResultC>)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Attestation_Session {
    pub Session_Plc:  Plc,
    pub Plc_Mapping:  HashMap<Plc, String>,
    pub PubKey_Mapping:  HashMap<Plc, String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolRunRequest {
    pub TYPE:  String,
    pub ACTION:  String,
    pub REQ_PLC:  Plc,
    pub TERM:  Term,
    pub RAWEV:  RawEv,
    pub ATTESTATION_SESSION: Attestation_Session
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolRunResponse {
    pub TYPE:  String,
    pub ACTION:  String,
    pub SUCCESS:  bool,
    pub PAYLOAD:  RawEv
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolAppraiseRequest {
    pub TYPE:  String,
    pub ACTION:  String,
    pub ATTESTATION_SESSION: Attestation_Session,
    pub TERM:  Term,
    pub REQ_PLC:  Plc,
    pub EVIDENCE:  Evidence,
    pub RAWEV:  RawEv
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolAppraiseResponse {
    pub TYPE:  String,
    pub ACTION:  String,
    pub SUCCESS:  bool,
    pub PAYLOAD:  AppResultC
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ASPRunRequest {
    pub TYPE:  String,
    pub ACTION:  String,
    pub ASP_ID: String,
    pub ASP_ARGS: ASP_ARGS,
    pub ASP_PLC:  Plc,
    pub ASP_TARG_ID: TARG_ID,
    pub RAWEV:  RawEv
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ASPRunResponse {
    pub TYPE:  String,
    pub ACTION:  String,
    pub SUCCESS:  bool,
    pub PAYLOAD:  RawEv
}
