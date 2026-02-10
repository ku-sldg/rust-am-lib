#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use anyhow::{Result, anyhow};
use base64::Engine;
use core::panic;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value, from_value};
use serde_stacker::Deserializer;
use std::collections::HashMap;
use std::fs;
use std::env;

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

pub fn get_rawev (e:Evidence) -> RawEvT {
    match e {
        (RawEv::RawEv(v), _) => {v}
    }
}

pub fn get_et (e:Evidence) -> EvidenceT {
    match e {
        (_, et) => {et}
    }
}

pub static EMPTY_EVIDENCE: Evidence = (RawEv::RawEv (vec![]), EvidenceT::mt_evt);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppSummReportValue {
    pub meta: String,
    pub result: bool
}

pub type AppraisalSummary = HashMap<ASP_ID, HashMap<TARG_ID, AppSummReportValue>>;

pub fn eval_asp (a:ASP, p:Plc, e:EvidenceT) -> Result<EvidenceT> {

        match a {
            ASP::ASPC(params) => {
                Ok(EvidenceT::asp_evt(p, params, Box::new(e)))
            }
            _ => {Ok(EvidenceT::mt_evt)}
        }
}

fn splitEv_T_l (sp:Split, e:EvidenceT) -> EvidenceT {
    match sp {
        Split{split1:SP::ALL, split2:_} => {e}
        _ => EvidenceT::mt_evt
    }
}

fn splitEv_T_r (sp:Split, e:EvidenceT) -> EvidenceT {
    match sp {
        Split{split1:_, split2:SP::ALL} => {e}
        _ => EvidenceT::mt_evt
    }
}

pub fn eval (p:Plc, e:EvidenceT, t:Term) -> Result<EvidenceT> {

    match t {
        Term::asp(a)=> {eval_asp(a, p.clone(), e)}
        Term::att(q, t1) => {eval(q, e,*t1)}
        Term::lseq(t1, t2) => {
            let e1 = eval(p.clone(), e, *t1)?;
            eval(p, e1, *t2)
        }
        Term::bseq(s, t1, t2) => {
            let e1 = eval(p.clone(), splitEv_T_l(s.clone(), e.clone()), *t1)?;
            let e2 = eval(p.clone(), splitEv_T_r(s, e), *t2)?;
            Ok(EvidenceT::split_evt(Box::new(e1), Box::new(e2)))
        }
        Term::bpar(s, t1, t2) => {
            let e1 = eval(p.clone(), splitEv_T_l(s.clone(), e.clone()), *t1)?;
            let e2 = eval(p.clone(), splitEv_T_r(s, e), *t2)?;
            Ok(EvidenceT::split_evt(Box::new(e1), Box::new(e2)))
        }

    }

}

pub fn add_key_to_json_args (k:String, v:serde_json::Value, old_v:serde_json::Value) -> serde_json::Value {


    let mut data: serde_json::Value = old_v.clone();

    if let Some(obj) = data.as_object_mut() {
        obj.insert(k, v);
        let res = serde_json::to_value(&obj).expect("hi");
        return res

    }
    else {
        if data.is_null() {
            let mut obj: serde_json::Map<String,Value> = serde_json::Map::new();
            obj.insert(k, v);
            let res = serde_json::to_value(&obj).expect("hi");
            return res
        }
        else {
            panic!("ASP_ARGS of the wrong form (not NULL or Object)")
            //return serde_json::Value::Null
        }
    }

}

pub fn add_provisioning_args_asp (a:ASP) -> ASP {

    let aid_key = "asp_id_appr".to_string();
    let tid_key = "targ_id_appr".to_string();

    match a {
        ASP::ASPC(ps) => {

            match ps {
                ASP_PARAMS { ASP_ID:aid, ASP_ARGS:args, ASP_PLC:p, ASP_TARG_ID:tid } => 
                    {
                        let new_args_1: Value = add_key_to_json_args(aid_key.clone(), Value::String(aid.clone()), args.clone());
                        let new_args: Value = add_key_to_json_args(tid_key, Value::String(tid.clone()), new_args_1);
                        let new_ps = ASP_PARAMS {ASP_ID: aid, ASP_ARGS: new_args, ASP_PLC:p, ASP_TARG_ID:tid};
                        return ASP::ASPC(new_ps)
                    }
            }
        }
        _ => {return a}
    }

}

pub fn add_provisioning_args (t:Term) -> Term {
    match t {
        Term::asp(a) => { Term::asp(add_provisioning_args_asp(a)) }
        Term::att(p, t1) => { Term::att(p, Box::new(add_provisioning_args(*t1))) }
        Term::lseq(t1, t2) => { Term::lseq( Box::new(add_provisioning_args(*t1)), Box::new(add_provisioning_args(*t2))) }
        Term::bseq(sp, t1, t2) => { Term::bseq(sp, Box::new(add_provisioning_args(*t1)), Box::new(add_provisioning_args(*t2))) }
        Term::bpar(sp, t1, t2) => { Term::bpar(sp, Box::new(add_provisioning_args(*t1)), Box::new(add_provisioning_args(*t2))) }
    }
}

pub static PROVISION_ASP_ID: &str = "provision_goldenevidence"; //executables/provision_goldenevidence
pub static ET_GOLDEN_STR: &str = "et_golden";
pub static ET_CTXT_STR: &str = "et_context";
pub static FILEPATH_GOLDEN_FIELD_STR: &str = "filepath_golden";
pub static ENV_VAR_GOLDEN_FIELD_STR: &str = "env_var_golden";

fn write_string_to_output_dir (maybe_out_dir:Option<String>, fp_suffix: String, default_mid_path:String, outstring:String) -> std::io::Result<String> {

    let fp_prefix : String = match &maybe_out_dir {
        Some(fp) => {
            fp.to_string()
        }
        None => {

            let cur_dir = env::current_dir()?;
            let cur_dir_string = cur_dir.to_str().unwrap();
            let default_path = default_mid_path;
            let default_prefix: String = format!("{cur_dir_string}/{default_path}");
            default_prefix
        }
    };

    let full_req_fp = format!("{fp_prefix}/{fp_suffix}");

    fs::create_dir_all(fp_prefix)?;
    fs::write(&full_req_fp, outstring)?;
    Ok(full_req_fp)
}

pub fn generate_golden_evidence_provisioning_args (p:&Plc, et:&EvidenceT, t:&Term, et_ctxt:&GlobalContext, old_args:Value) -> Result<Value> {
    let golden_et = eval(p.clone(),et.clone(), t.clone())?;

    let file_json_val : (EvidenceT, GlobalContext) = (et.clone(), et_ctxt.clone());

    let file_json_string = serde_json::to_string(&file_json_val)?;
    let file_json_mid_dir: String = "testing/outputs/".to_string();
    let file_json_name: String = "temp_golden_evidence_env.json".to_string();

    write_string_to_output_dir(None, file_json_name.clone(), file_json_mid_dir, file_json_string)?;

    //let golden_et_json = serde_json::to_value(&golden_et)?;
    //let et_ctxt_json = serde_json::to_value(&et_ctxt)?;

    let evidence_json_fp = serde_json::to_value(&file_json_name)?;

    let ctxt_json_fp = serde_json::to_value("")?;


    let new_args = add_key_to_json_args(ET_GOLDEN_STR.to_string(), evidence_json_fp, old_args);
    let new_args_final = add_key_to_json_args(ET_CTXT_STR.to_string(), ctxt_json_fp, new_args);
    return Ok(new_args_final);
}

pub fn add_golden_evidence_provisioning_args_asp (p:&Plc, init_et:&EvidenceT, t:&Term, et_ctxt:&GlobalContext, a:ASP) -> ASP {
    match a {
        ASP::ASPC(ps) => {

            match ps.clone() {
                ASP_PARAMS { ASP_ID:aid, ASP_ARGS:args, ASP_PLC:pid, ASP_TARG_ID:tid } => 
                    {
                        if aid == PROVISION_ASP_ID.to_string() {
                            let new_args = generate_golden_evidence_provisioning_args(&p, &init_et, &t, et_ctxt, args).expect("hi");
                            let new_ps = ASP_PARAMS {ASP_ID: aid, ASP_ARGS: new_args, ASP_PLC:pid, ASP_TARG_ID:tid};
                            return ASP::ASPC(new_ps)
                        }
                        else { return ASP::ASPC(ps) }
                    }
            }
        }
        _ => {return a}
    }
}

pub fn add_golden_evidence_provisioning_args (p:&Plc, init_et:&EvidenceT, t_golden:&Term, et_ctxt:&GlobalContext, t:Term) -> Term {
    match t {
        Term::asp(a) => { Term::asp(add_golden_evidence_provisioning_args_asp(p, init_et, t_golden, et_ctxt, a)) }
        Term::att(q, t1) => { Term::att(q, Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t1))) }
        Term::lseq(t1, t2) => { Term::lseq( Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t1)), Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t2))) }
        Term::bseq(sp, t1, t2) => { Term::bseq(sp, Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t1)), Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t2))) }
        Term::bpar(sp, t1, t2) => { Term::bpar(sp, Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t1)), Box::new(add_golden_evidence_provisioning_args(p, init_et, t_golden, et_ctxt, *t2))) }
    }
}

pub fn build_golden_evidence_provisioning_asp (fp:&str) -> Term {

    let args: Value = json!({FILEPATH_GOLDEN_FIELD_STR: fp,
                             ENV_VAR_GOLDEN_FIELD_STR: ""});
    let my_plc: Plc = "PROV_PLC".to_string();
    let my_targ: Plc = "PROV_TARG".to_string();
    let params: ASP_PARAMS = ASP_PARAMS { ASP_ID: PROVISION_ASP_ID.to_string(), ASP_ARGS: args, ASP_PLC: my_plc, ASP_TARG_ID: my_targ };
    Term::asp(ASP::ASPC(params))
}

pub fn append_provisioning_term (fp:&str, p:&Plc, init_et:&EvidenceT, t_golden: &Term, et_ctxt:&GlobalContext, t:Term) -> Term {

    let prov_asp: Term = build_golden_evidence_provisioning_asp(fp);
    let new_t_golden: Term = add_provisioning_args(t_golden.clone());
    let prov_term: Term = add_golden_evidence_provisioning_args(p, init_et, &new_t_golden, et_ctxt, prov_asp);
    let new_term: Term = Term::lseq(Box::new(t), Box::new(prov_term));
    add_provisioning_args(new_term)
    /*
    let prov_term_final: Term = add_provisioning_args(prov_term.clone());
    let old_term_final: Term = add_provisioning_args(t);
    Term::lseq(Box::new(old_term_final), Box::new(prov_term_final))
    */
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
    pub APPRAISAL_RESULT: bool,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ASP_ARGS_ReadfileRange {
    filepath: String,
    start_index: usize,
    end_index: usize, 
    metadata: String, 
    meta: String,
    env_var_golden: String,
    filepath_golden: String
}

fn add_asp_summary(par:ASP_PARAMS, ls:RawEvT, s:AppraisalSummary) -> Result<AppraisalSummary> {

    let i = par.ASP_ID;
    let tid = par.ASP_TARG_ID;
    let asp_args = par.ASP_ARGS;

    let v: std::result::Result<ASP_ARGS_ReadfileRange, serde_json::Error> = serde_json::from_value(asp_args);


    let meta_string = 
        match v {
            Ok(x) => {x.meta}
            _ => {"".to_string()}
        };

    let b = check_simple_appraised_rawev(ls);
    let mut m = s.clone();
    let maybe_inner_map = m.get(&i);
    let mut inner_map = 
        match maybe_inner_map {
            None => {HashMap::new()}
            Some(mm) => mm.clone()
        };
    let app_report_val: AppSummReportValue = AppSummReportValue { meta: meta_string, result: b };
    inner_map.insert(tid, app_report_val);
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
                                    let (r1, _) = peel_n_rawev(n, r)?;
                                    add_asp_summary(par, r1, s)
                                }
                                _ => {Ok(s)}
                            }
                        }
                        FWD::EXTEND => {
                            match evsig.EvOutSig {
                                EvOutSig::OutN(n) => {
                                    //print!("\n\nin EXTEND arm\n\n");
                                    let (r1, rest) = peel_n_rawev(n, r)?;
                                    let res = add_asp_summary(par, r1, s)?;
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
            println!("\t{}(meta=\"{}\"): {}", inner_key, inner_val.meta, (bool_to_passed_string(inner_val.result)))
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
            eprintln!("\t{}(meta=\"{}\"): {}", inner_key, inner_val.meta, (bool_to_passed_string(inner_val.result)))
        }
    }
    eprintln!("\nAppraisal Summary: {}\n", bool_to_passed_string(appsumm_bool));
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
    let reqval = deserialize_deep_json(json_req).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ASPRunRequest: {error:?}"));
    });
    let req: ASPRunRequest = from_value(reqval).unwrap_or_else(|error| {
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

fn deserialize_deep_json(json_data: &str) -> serde_json::Result<Value> {
    let mut de = serde_json::de::Deserializer::from_str(json_data);
    de.disable_recursion_limit(); // This method is only available with the feature
    
    // Wrap with serde_stacker's Deserializer to use a dynamically growing stack
    let stacker_de = Deserializer::new(&mut de);
    
    // Deserialize the data
    let value = Value::deserialize(stacker_de)?;
    
    Ok(value)
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

    eprintln!("--------START of handle_body()----------");
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ASPRunRequest JSON>", args[0]);
        respond_with_failure("Invalid arguments to ASP".to_string());
    }

    let json_req = &args[1];

    eprintln!("--------GOT BEYOND json_req= in handle_body()----------");

    let reqval = deserialize_deep_json(json_req).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ASPRunRequest: {error:?}"));
    });
    let req: ASPRunRequest = from_value(reqval).unwrap_or_else(|error| {
        respond_with_failure(format!("Failed to parse ASPRunRequest: {error:?}"));
    });

    match body(rawev_to_vec(req.RAWEV), req.ASP_ARGS) {
        Ok(ev) => {
            //panic!("\\n\n GOT TO Ok branch in handle_body()\n\n\n");

            if req.ASP_ID == "provision_goldenevidence".to_string()
                {   //eprintln!("\n\n\n\n\n\n\n\n\n\n\n\nResponse success: {}\n\n\n\n\n\n\n\n\n\n\n\n", hi);
                    panic!("\\n\n GOT TO Ok branch in handle_body() of provision_goldenevidence ASP\n\n\n") }
            let response = successfulASPRunResponse(vec_to_rawev(ev));
            let hi = response.SUCCESS;
            let resp_json = serde_json::to_string(&response).unwrap_or_else(|error| {
                panic!("\\n\n GOT TO error handler of serde_json::to_string(&response) in handle_body()\n\n\n");
                respond_with_failure(format!("Failed to json.encode response: {error:?}"));
            });
            println!("{resp_json}");

            /*
            if req.ASP_ID == "readfile_range".to_string()
                {   eprintln!("\n\n\n\n\n\n\n\n\n\n\n\nResponse success: {}\n\n\n\n\n\n\n\n\n\n\n\n", hi);
                    panic!("\\n\n GOT beyond println!(resp_json); in handle_body()\n\n\n") }
            */
            if req.ASP_ID == "provision_goldenevidence".to_string()
                {   eprintln!("\n\n\n\n\n\n\n\n\n\n\n\nResponse success: {}\n\n\n\n\n\n\n\n\n\n\n\n", hi);
                    panic!("\\n\n GOT beyond println!(resp_json); in handle_body()\n\n\n") }
            std::process::exit(0);
        }
        Err(reason) => {
            if req.ASP_ID == "provision_goldenevidence".to_string()
                {   //eprintln!("\n\n\n\n\n\n\n\n\n\n\n\nResponse success: {}\n\n\n\n\n\n\n\n\n\n\n\n", hi);
                    panic!("\\n\n GOT TO Err branch in handle_body() of provision_goldenevidence ASP\n\n\n Reason:{}", reason) }
            //panic!("\\n\n GOT TO error in handle_body()\n\n\n");
            respond_with_failure(reason.to_string());
        }
    }
}