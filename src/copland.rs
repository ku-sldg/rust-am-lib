#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::Result;
//use anyhow::anyhow;
use base64::Engine;
use core::panic;
use serde::{Deserialize, Serialize};
use serde_json::{Value};
use std::collections::HashMap;

pub type Plc = String;
pub type N_ID = String;
pub type ASP_ID = String;
pub type TARG_ID = String;
pub type ASP_ARGS = serde_json::Value;

// tcp.rs (tcp utilities)
//use tokio::net::TcpSocket;
//use tokio::net::TcpStream;
//use std::net::SocketAddr;
//use tokio::io::{AsyncWriteExt, AsyncReadExt};
//use tokio::runtime::Runtime;

static APPRAISAL_SUCCESS_RESPONSE: &str = "";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ASP_PARAMS {
    pub ASP_ID: ASP_ID,
    pub ASP_ARGS: ASP_ARGS,
    pub ASP_PLC: Plc,
    pub ASP_TARG_ID: TARG_ID,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(tag = "FWD_CONSTRUCTOR", content = "FWD_BODY")]
pub enum FWD {
    REPLACE,
    WRAP,
    UNWRAP,
    EXTEND
}

    /*
    COMP,
    ENCR,
    EXTD(String),
    KILL,
    KEEP,
    */

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(tag = "EvInSig_CONSTRUCTOR", content = "EvInSig_BODY")]
pub enum EvInSig {
    ALL,
    NONE
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "EvOutSig_CONSTRUCTOR", content = "EvOutSig_BODY")]
pub enum EvOutSig {
    OutN(String),
    OutUnwrap
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvSig {
    pub FWD: FWD,
    pub EvInSig: EvInSig,
    pub EvOutSig: EvOutSig
}

pub type ASP_Type_Env = HashMap<ASP_ID, EvSig>;
pub type ASP_Compat_MapT = HashMap<ASP_ID, ASP_ID>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GlobalContext {
    pub ASP_Types: ASP_Type_Env,
    pub ASP_Comps: ASP_Compat_MapT
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "EvidenceT_CONSTRUCTOR", content = "EvidenceT_BODY")]
pub enum EvidenceT {
    mt_evt,
    nonce_evt(N_ID),
    asp_evt(Plc, ASP_PARAMS, Box<EvidenceT>),
    left_evt(Box<EvidenceT>),
    right_evt(Box<EvidenceT>),
    split_evt(Box<EvidenceT>, Box<EvidenceT>)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SP {
    ALL,
    NONE,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "ASP_CONSTRUCTOR", content = "ASP_BODY")]
pub enum ASP {
    NULL,
    CPY,
    ASPC(ASP_PARAMS),    //ASPC(SP, FWD, ASP_PARAMS),
    SIG,
    HSH,
    ENC(Plc),
    APPR
}

pub type Split = (SP, SP);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "TERM_CONSTRUCTOR", content = "TERM_BODY")]
pub enum Term {
    asp(ASP),
    att(Plc, Box<Term>),
    lseq(Box<Term>, Box<Term>),
    bseq(Split, Box<Term>, Box<Term>),
    bpar(Split, Box<Term>, Box<Term>),
}

//type BS = bytestring::ByteString;

type RawEvT = Vec<String>; //Vec<BS>;

pub type ASP_RawEv = Vec<Vec<u8>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(untagged)]
//#[serde(tag = "RawEv_CONSTRUCTOR", content = "RawEv_BODY")]
pub enum RawEv {
    RawEv(RawEvT),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Evidence {
    pub RAWEV: RawEv,
    pub EVIDENCET: EvidenceT
}

pub static EMPTY_EVIDENCE: Evidence = 
    Evidence { RAWEV: RawEv::RawEv (vec![]),
        EVIDENCET: EvidenceT::mt_evt };

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
pub struct Attestation_Session {
    pub Session_Plc: Plc,
    pub Plc_Mapping: HashMap<Plc, String>,
    pub PubKey_Mapping: HashMap<Plc, String>,
    pub Session_Context: GlobalContext
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolRunRequest {
    pub TYPE: String,
    pub ACTION: String,
    pub REQ_PLC: Plc,
    pub TO_PLC: Plc,
    pub TERM: Term,
    pub EVIDENCE: Evidence,
    pub ATTESTATION_SESSION: Attestation_Session,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtocolRunResponse {
    pub TYPE: String,
    pub ACTION: String,
    pub SUCCESS: bool,
    pub PAYLOAD: Evidence,
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
pub fn respond_with_failure(reason: String) -> ! {
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

pub fn get_env_var_val (key:String) -> Result<String> {

    if key == "" {
        Ok("".to_string()) 
    }
    else { 
    let env_var_string = match std::env::var(&key) {
        Ok(val) => val,
        Err(_e) => {
            panic!("Did not set environment variable {}\n", key)
        }
    };
    Ok (env_var_string) }
}

fn aspc_args_swap(params:ASP_PARAMS, args:Value) -> ASP_PARAMS {
    ASP_PARAMS { ASP_ARGS: args,
                 ASP_ID: params.ASP_ID,
                 ASP_PLC: params.ASP_PLC,
                 ASP_TARG_ID: params.ASP_TARG_ID,
                 }
}

pub fn term_add_args(t:Term, args:Value) -> Term {
    match t {

        Term::asp(ref a) => {
            match a {
                ASP::ASPC(params) => {Term::asp(ASP::ASPC(aspc_args_swap(params.clone(), args)))}
                _ => {t}
            }
        }

        Term::att(q,t1) => {
            let t1: Term = term_add_args(*t1, args);
            Term::att(q, Box::new(t1)) 
        }

        Term::lseq(t1,t2) => 
            { 
                let t1: Term = term_add_args(*t1, args.clone());
                let t2: Term = term_add_args(*t2, args.clone());

                Term::lseq(Box::new(t1), Box::new(t2))
            }

        Term::bseq(sp, t1,t2) => 
        { 
            let t1: Term = term_add_args(*t1, args.clone());
            let t2: Term = term_add_args(*t2, args.clone());

            Term::bseq(sp, Box::new(t1), Box::new(t2))
        }

        Term::bpar(sp, t1,t2) => 
        { 
            let t1: Term = term_add_args(*t1, args.clone());
            let t2: Term = term_add_args(*t2, args.clone());

            Term::bpar(sp, Box::new(t1), Box::new(t2))
        }
    }
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

/*
async fn connect_tcp_stream (server_uuid_string:String, client_uuid_string:String) -> std::io::Result<tokio::net::TcpStream> {

    let socket: TcpSocket = TcpSocket::new_v4()?;

    let server_addr: SocketAddr = server_uuid_string.parse().unwrap();

    let maybe_client_addr_string: Option<String> =
        if client_uuid_string == "".to_string()
        { None }
        else 
        {
            Some (client_uuid_string)
        };

    match maybe_client_addr_string {
        Some (client_addr_string) => {

            let client_addr: SocketAddr = client_addr_string.parse().unwrap();
            socket.set_reuseaddr(true)?;
            socket.bind(client_addr)?;

            eprintln!("\n{}{}{}{}", "Trying to connect to server at address:  ", server_addr, " from FIXED client address: ", client_addr);
            let stream = socket.connect(server_addr).await?;
            Ok(stream)

        }
        None => {
            eprintln!("\n{}{}{}", "Trying to connect to server at address:  ", server_addr, " from EPHEMERAL (OS-chosen) client address");
            let stream = socket.connect(server_addr).await?;
            Ok(stream)

        }
    }
}

#[allow(non_snake_case)]
async fn am_sendRec_string (s:String, mut stream:TcpStream) -> std::io::Result<String> {
    let sbytes = s.as_bytes();
    let sbytes_len: u32 = sbytes.len().try_into().unwrap();

    // Write a buffer of bytes representing the (u32) size of the string to be sent
    let mut wtr = vec![];
    AsyncWriteExt::write_u32(& mut wtr,sbytes_len).await?;//.unwrap();
    stream.write_all(&wtr).await?;

    // Write the string as bytes
    stream.try_write(s.as_bytes())?;

    // This is a hack to read 4 bytes from the stream (peeling off the response buffer size)
    // TODO:  We should probably use/decode this value in the future if we keep this approach
    let mut x:[u8; 4] = [0u8;4];
    stream.read_exact(&mut x).await?;
    //stream.try_read(&mut x)?;

    // Read in response string from stream
    let mut str_in : String = String::new();
    stream.read_to_string(&mut str_in).await?;

    // Clone and return response string
    let str_out : String = str_in.clone();
    Ok (str_out)
}

pub fn handle_am_req_resp_body() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ProtocolRunRequest JSON>", args[0]);
        respond_with_failure("Invalid arguments to AM".to_string());
    }

    let json_req = &args[1];
    let req: ProtocolRunRequest = serde_json::from_str(json_req).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ProtocolRunRequest: {error:?}"));
    });

    let to_plc : Plc = req.TO_PLC.clone();

    let to_sess : Attestation_Session = req.ATTESTATION_SESSION.clone();
    let to_plcmap: HashMap<String, String> = to_sess.Plc_Mapping.clone();
    let maybe_to_uuid  = to_plcmap.get(&to_plc);

    let to_uuid = match maybe_to_uuid {

        Some (val) => {val }
        _ => {""}

    };

    let to_uuid_string : String = to_uuid.to_string();

    let vreq : ProtocolRunRequest = req.clone();

    let req_str = serde_json::to_string(&vreq)?;

    let val = async {

    let stream = connect_tcp_stream(to_uuid_string, "".to_string()).await?;
    eprintln!("\nTrying to send ProtocolRunRequest: \n");
    eprintln!("{req_str}\n");

    let resp_str = am_sendRec_string(req_str,stream).await?;
    eprintln!("Got a TCP Response String: \n");
    eprintln!("{resp_str}\n");

    /*
    let resp : ProtocolRunResponse = serde_json::from_str(&resp_str)?;
    eprintln!("Decoded ProtocolRunResponse: \n");
    eprintln!("{:?}\n", resp);
    */

    println!("{resp_str}");

    Ok::<(), std::io::Error> (())
    };

    let runtime: Runtime = tokio::runtime::Runtime::new().unwrap();

    match runtime.block_on(val) {
        Ok(x) => x,
        Err(_) => println!("Runtime failure in rust-am-client main.rs"),
    };

    std::process::exit(0);

}
    */
