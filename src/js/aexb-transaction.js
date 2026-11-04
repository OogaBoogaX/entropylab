// Verify supplied AEXB signature slots against the PSBT already carried in M3.
// No wallet ownership, chain-state, fee approval, finalization or broadcast claim.
import { psbtInspectDoc } from "./psbt-wasm.js";
import { psbtSegwitV0Context } from "./psbt-signer-audit-verify.js";
import { sha256, hash160 } from "./hashes.js";
import { secp256k1 } from "./secp256k1.js";
const equal = (a,b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length===b.length && a.every((v,i)=>v===b[i]);
const bad = reason => ({ok:false,reason,checkedSlots:0});
function keyInScript(script, key, form) {
  if (script.length===25 && script[0]===0x76 && script[1]===0xa9 && script[2]===20 && script[23]===0x88 && script[24]===0xac)
    return (form === "p2wpkh" || form === "p2sh-p2wpkh") && (!key || equal(script.slice(3,23), hash160(key)));
  if (form !== "p2wsh" && form !== "p2sh-p2wsh") return false;
  // Protocol v1's standard SegWit multisig: canonical compressed-key pushes.
  if (script.length<3 || script.at(-1)!==0xae) return false;
  const m=script[0]-0x50,n=script.at(-2)-0x50;
  if(m<1 || n<m || n>16 || script.length!==3+34*n)return false;
  const seen=new Set();let found=false;
  for(let i=0;i<n;i++) {
    const at=1+34*i;if(script[at]!==33)return false;
    const pub=script.slice(at+1,at+34);
    try { secp256k1.Point.fromBytes(pub); } catch { return false; }
    const id=Array.from(pub).join(',');if(seen.has(id))return false;seen.add(id);
    if(!key || equal(pub,key))found=true;
  }
  return found;
}
// Caller must first validate canonical stage-4 slots and transcript binding with aexbVerify.
export function verifyAexbTransaction(reveal, signatures) {
  try {
    const psbt=reveal?.psbt, slots=signatures?.slots;
    if(!(psbt instanceof Uint8Array) || !psbt.length || psbt.length>2065600 || !Array.isArray(slots) || !slots.length || slots.length>128)
      return bad("TRANSACTION_INPUT_INVALID");
    if(psbt.length*slots.length>32*1024*1024)return bad("TRANSACTION_CHECK_LIMIT");
    const digest=sha256(psbt);
    if(!equal(digest,reveal.psbtDigest) || !equal(digest,signatures.psbtDigest))return bad("TRANSACTION_DIGEST_MISMATCH");
    const doc=psbtInspectDoc(psbt);
    if(doc.psbtVersion!==0 || doc.errorCount || doc.problemsTruncated || doc.txSanityError || doc.rustBitcoinError)
      return bad("TRANSACTION_INVALID");
    // Bound the newly whole-PSBT walk as well as the supplied signature work.
    if(psbt.length*Math.max(doc.inputs.length,slots.length)>32*1024*1024)return bad("TRANSACTION_CHECK_LIMIT");
    const contexts=new Map();
    for(let index=0;index<doc.inputs.length;index++) {
      const input=doc.inputs[index];
      const declared=input.find(p=>p.name==="PSBT_IN_SIGHASH_TYPE");
      if(declared && declared.decoded?.sighashType!==1)return bad("TRANSACTION_SIGHASH_UNSUPPORTED");
      // This observer cannot establish attribution of stripped finalized inputs.
      // Refuse these explicitly rather than silently exempting them from checks.
      if(input.some(p=>p.name==="PSBT_IN_FINAL_SCRIPTSIG" || p.name==="PSBT_IN_FINAL_SCRIPTWITNESS"))return bad("TRANSACTION_ALREADY_FINALIZED");
      if(input.some(p=>p.name?.startsWith("PSBT_IN_TAP_")))return bad("TRANSACTION_CONTEXT_UNSUPPORTED");
      const context=psbtSegwitV0Context(doc,index);
      if(!context || !keyInScript(context.scriptCode, undefined, context.form))return bad("TRANSACTION_CONTEXT_UNSUPPORTED");
      contexts.set(index,context);
    }
    for(const slot of slots) {
      const index=slot.inputIndex;
      if(!Number.isInteger(index) || index<0 || index>=doc.inputs.length || slot.sighashType!==1)return bad("TRANSACTION_SLOT_INVALID");
      const context=contexts.get(index);
      if(!context)return bad("TRANSACTION_CONTEXT_UNSUPPORTED");
      if(!keyInScript(context.scriptCode,slot.signerPubkey,context.form))return bad("TRANSACTION_KEY_MISMATCH");
      if(!equal(context.digest,slot.messageHash))return bad("TRANSACTION_MESSAGE_HASH_MISMATCH");
      if(!secp256k1.verify(slot.signature,context.digest,slot.signerPubkey,{prehash:false,lowS:true}))return bad("TRANSACTION_SIGNATURE_INVALID");
    }
    return {ok:true,reason:null,checkedSlots:slots.length,totalInputs:doc.inputs.length,checkedInputs:[...new Set(slots.map(slot=>slot.inputIndex))].sort((a,b)=>a-b)};
  } catch { return bad("TRANSACTION_INVALID"); }
}
