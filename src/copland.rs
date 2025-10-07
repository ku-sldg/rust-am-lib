#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::{Result, anyhow};
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

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(tag = "EvInSig_CONSTRUCTOR", content = "EvInSig_BODY")]
pub enum EvInSig {
    ALL,
    NONE
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "EvOutSig_CONSTRUCTOR", content = "EvOutSig_BODY")]
pub enum EvOutSig {
    OutN(u32),
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
    ASPC(ASP_PARAMS),
    SIG,
    HSH,
    ENC(Plc),
    APPR
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Split {
    pub split1: SP,
    pub split2: SP
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "TERM_CONSTRUCTOR", content = "TERM_BODY")]
pub enum Term {
    asp(ASP),
    att(Plc, Box<Term>),
    lseq(Box<Term>, Box<Term>),
    bseq(Split, Box<Term>, Box<Term>),
    bpar(Split, Box<Term>, Box<Term>),
}

type RawEvT = Vec<String>;

pub type ASP_RawEv = Vec<Vec<u8>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(untagged)]
//#[serde(tag = "RawEv_CONSTRUCTOR", content = "RawEv_BODY")]
pub enum RawEv {
    RawEv(RawEvT),
}

pub type Evidence = (RawEv, EvidenceT);

pub static EMPTY_EVIDENCE: Evidence = (RawEv::RawEv (vec![]), EvidenceT::mt_evt);

pub type AppraisalSummary = HashMap<ASP_ID, HashMap<TARG_ID, bool>>;

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
pub struct ASPRunRequest {
    pub TYPE: String,
    pub ACTION: String,
    pub ASP_ID: String,
    pub ASP_ARGS: ASP_ARGS,
    pub ASP_PLC: Plc,
    pub ASP_TARG_ID: TARG_ID,
    pub RAWEV: RawEv,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ASPRunResponse {
    pub TYPE: String,
    pub ACTION: String,
    pub SUCCESS: bool,
    pub PAYLOAD: RawEv,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppraisalSummaryRequest {
    pub TYPE: String,
    pub ACTION: String,
    pub ATTESTATION_SESSION: Attestation_Session,
    pub EVIDENCE: Evidence
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppraisalSummaryResponse {
    pub TYPE: String,
    pub ACTION: String,
    pub SUCCESS: bool,
    pub PAYLOAD: AppraisalSummary
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceSliceRequest {
    pub TYPE: String,
    pub ACTION: String,
    pub GLOBAL_CONTEXT: GlobalContext,
    pub EVIDENCE: Evidence, 
    pub ASP_PARAMS: ASP_PARAMS
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceSliceResponse {
    pub TYPE: String,
    pub ACTION: String,
    pub SUCCESS: bool,
    pub PAYLOAD: RawEv
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


fn et_size(g:GlobalContext, et:EvidenceT) -> Result<u32> {

    match et {
        EvidenceT::mt_evt => {Ok(0)}
        EvidenceT::asp_evt(_,par, et2) => {
            match g.ASP_Types.get(&par.ASP_ID) {
                None => {Ok(0)}
                Some(evsig) => {
                    match evsig.FWD {
                        FWD::REPLACE => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {Ok(n)}
                                _ => {Ok(0)}
                            }
                        }
                        FWD::EXTEND => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {

                                    let n2 = et_size(g, *et2)?;
                                        Ok (n + n2)
                                    
                                }
                                _ => {Ok(0)}
                            }
                        }
                        _ => {Ok(0)} /* TODO: add FWD::WRAP, FWD::UNWRAP cases once supported */
                    }            
                }
            }
        }
        EvidenceT::left_evt(e2) => {
            et_size(g, *e2)
        }
        EvidenceT::right_evt(e2) => {
            et_size(g, *e2)
        }
        EvidenceT::split_evt(e1, e2) => {
            let n1 = et_size(g.clone(), *e1)?;
            let n2 = et_size(g, *e2)?;
            Ok(n1 + n2)
        }
        EvidenceT::nonce_evt(_) => {Ok(0)}
    }
}

fn peel_n_rawev (n:u32, ls:RawEvT) -> Result<(RawEvT, RawEvT)> {

    match n {

        0 => {Ok((vec![], ls))}

        n2 => {

            if ls.is_empty() {Ok((vec![], vec![]))} // TODO: error
            else {
                let x = ls.first().expect("hi").to_string();
                let ls2 = ls[1..].to_vec();
                let xvec = vec![x].to_vec();

                let (ls1, ls2) = peel_n_rawev(n2 - 1, ls2.clone())?;



                let res = xvec.clone().into_iter().chain(ls1.clone().into_iter()).collect();

                Ok((res, ls2))
            }
        }
    }
}

fn check_simple_appraised_rawev (ls:RawEvT) -> bool {
    if ls == vec![""] {true}
    else {false}
}

fn add_asp_summary(i:ASP_ID, tid:TARG_ID, ls:RawEvT, s:AppraisalSummary) -> Result<AppraisalSummary> {

    let b = check_simple_appraised_rawev(ls);
    let mut m = s.clone();
    let maybe_inner_map = m.get(&i);
    let mut inner_map = 
        match maybe_inner_map {
            None => {HashMap::new()}
            Some(mm) => mm.clone()
        };
    inner_map.insert(tid, b);
    m.insert(i, inner_map);
    
    Ok(m.clone())
}

static EV_SLICE_ERROR_STR : &str = "Error in do_EvidenceSlice_inner() in copland.rs";

fn do_EvidenceSlice_inner(et:EvidenceT, r:RawEvT, g:GlobalContext, ps:ASP_PARAMS) -> Result<RawEvT> {

    match et {
        EvidenceT::mt_evt => {Err(anyhow!(EV_SLICE_ERROR_STR))}
        EvidenceT::nonce_evt(_) => {Err(anyhow!(EV_SLICE_ERROR_STR))}
        EvidenceT::split_evt(et1, et2) => {

            let et1_size= et_size(g.clone(),*et1.clone())?;
            let et2_size = et_size(g.clone(), *et2.clone())?;

            let (r1, rest) = peel_n_rawev(et1_size, r)?;

            let e1_res = do_EvidenceSlice_inner(*et1, r1, g.clone(), ps.clone());

            match e1_res {
                Ok(v) => {Ok(v)}

                _ => {
                    let (r2, _) = peel_n_rawev(et2_size, rest)?;
                    do_EvidenceSlice_inner(*et2, r2, g, ps)
                }
            }
        }
        EvidenceT::left_evt(et2) => {
            do_EvidenceSlice_inner(*et2, r, g, ps)
        }
        EvidenceT::right_evt(et2) => {
            do_EvidenceSlice_inner(*et2, r, g, ps)
        }
        EvidenceT::asp_evt(_, par, et2 ) => {

            let aid = par.ASP_ID.clone();
            let tid = par.ASP_TARG_ID;

            let n = 
            match g.ASP_Types.get(&aid) {
                None => {Err(anyhow!(EV_SLICE_ERROR_STR))}
                Some(evsig) => {
                    match evsig.FWD {
                        FWD::REPLACE => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {
                                    Ok(n)
                                }
                                _ => {Err(anyhow!(EV_SLICE_ERROR_STR))}
                            }
                        }
                        FWD::EXTEND => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {
                                    Ok(n)
                                }
                                _ => {Err(anyhow!(EV_SLICE_ERROR_STR))} /* TODO: add OutUnWrap cases once supported */
                            }            
                        }

                        _ => {Err(anyhow!(EV_SLICE_ERROR_STR))} /* TODO: add FWD::WRAP, FWD::UNWRAP cases once supported */
                    }
                }
            }?;

            let (r1, rest) = peel_n_rawev(n, r)?;
            
            if (aid, tid) == (ps.ASP_ID.clone(), ps.ASP_TARG_ID.clone()) {
                Ok(r1)
            }
            else {       
                do_EvidenceSlice_inner(*et2, rest, g, ps)
            }
        }      
    }
}

pub fn do_EvidenceSlice(et:EvidenceT, r:RawEvT, g:GlobalContext, ps:ASP_PARAMS) -> Result<RawEvT> {
    do_EvidenceSlice_inner(et, r, g, ps)
}

fn do_AppraisalSummary_inner(et:EvidenceT, r:RawEvT, g:GlobalContext, s:AppraisalSummary) -> Result<AppraisalSummary> {

    match et {
        EvidenceT::mt_evt => {Ok(s)}
        EvidenceT::nonce_evt(_) => {Ok(s)}
        EvidenceT::split_evt(et1, et2) => {

            let et1_size= et_size(g.clone(),*et1.clone())?;
            let et2_size = et_size(g.clone(), *et2.clone())?;

            let (r1, rest) = peel_n_rawev(et1_size, r)?;
            //print!("\net1_size: {:?}", et1_size);
            //print!("\nr1: {:?}", r1);
            let (r2, _) = peel_n_rawev(et2_size, rest)?;

            let s1 = do_AppraisalSummary_inner(*et1, r1.clone(), g.clone(), s)?;

            do_AppraisalSummary_inner(*et2, r2, g, s1)
        }
        EvidenceT::left_evt(et2) => {
            do_AppraisalSummary_inner(*et2, r, g, s)
        }
        EvidenceT::right_evt(et2) => {
            do_AppraisalSummary_inner(*et2, r, g, s)
        }
        EvidenceT::asp_evt(_, par, et2 ) => {

            match g.ASP_Types.get(&par.ASP_ID) {
                None => {Ok(s)}
                Some(evsig) => {
                    match evsig.FWD {
                        FWD::REPLACE => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {
                                    /*
                                    print!("\n\nin REPLACE arm\n\n");
                                    print!("\nn: {:?}", n);
                                    print!("\nr: {:?}", r);
                                    */
                                    let (r1, _) = peel_n_rawev(n, r)?;
                                    add_asp_summary(par.ASP_ID.to_string(), par.ASP_TARG_ID.to_string(), r1, s)
                                }
                                _ => {Ok(s)}
                            }
                        }
                        FWD::EXTEND => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {
                                    //print!("\n\nin EXTEND arm\n\n");
                                    let (r1, rest) = peel_n_rawev(n, r)?;
                                    let res = add_asp_summary(par.ASP_ID.to_string(), par.ASP_TARG_ID.to_string(), r1, s)?;
                                    do_AppraisalSummary_inner(*et2, rest, g, res)
                                }
                                _ => {Ok(s)}
                            }
                        }
                        _ => {Ok(s)} /* TODO: add FWD::WRAP, FWD::UNWRAP cases once supported */
                    }            
                }
            }
        }
    }
}

pub fn do_AppraisalSummary(et:EvidenceT, r:RawEvT, g:GlobalContext) -> Result<AppraisalSummary> {
    do_AppraisalSummary_inner(et, r, g, HashMap::new())
}

fn bool_to_passed_string (b:bool) -> String {
    if b {"PASSED".to_string()}
    else {"FAILED".to_string()}
}

pub fn print_appsumm(appsumm:AppraisalSummary, appsumm_bool: bool) -> () {

    println!("---------------------------------------------------------------");
    println!("Appraisal Summary: {}\n", bool_to_passed_string(appsumm_bool));
    
    for (key, value) in appsumm.into_iter() {
        println!("{}:", key);
        for (inner_key, inner_val) in value.into_iter() {
            println!("\t{}: {}", inner_key, (bool_to_passed_string(inner_val)))
        }
    }
    println!("---------------------------------------------------------------");
    println!();
}

pub fn eprint_appsumm(appsumm:AppraisalSummary, appsumm_bool: bool) -> () {

    eprintln!("---------------------------------------------------------------");
    eprintln!("Appraisal Summary: {}\n", bool_to_passed_string(appsumm_bool));
    
    for (key, value) in appsumm.into_iter() {
        eprintln!("{}:", key);
        for (inner_key, inner_val) in value.into_iter() {
            eprintln!("\t{}: {}", inner_key, (bool_to_passed_string(inner_val)))
        }
    }
    eprintln!("---------------------------------------------------------------");
    eprintln!();
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

pub fn rawev_to_vec(rawev: RawEv) -> Vec<Vec<u8>> {
    match rawev {
        RawEv::RawEv(rawevt) => rawevt.iter().map(|base64| base64_to_vec(&base64)).collect(),
    }
}

pub fn vec_to_rawev(vec: Vec<Vec<u8>>) -> RawEv {
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