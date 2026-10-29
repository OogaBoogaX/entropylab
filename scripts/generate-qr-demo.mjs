// PUBLIC TEST FIXTURES ONLY. Fixed keys/nonces, invented outpoints, no funds.
// This generator is never imported into the application. No randomness is used.
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction, p2wpkh, p2pkh } from "@scure/btc-signer";
import { secp256k1 as curve } from "@noble/curves/secp256k1.js";
import { aexbEncodePackage } from "../src/js/aexb.js";
import { hashesReady } from "../src/js/hashes.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { hodlUrEncodeMessage, hodlCborBstr } from "../src/js/psbt-ur.js";
await hashesReady; await secp256k1Ready;
const hex=b=>Buffer.from(b).toString("hex"), b32=n=>Uint8Array.from(Buffer.from(n.toString(16).padStart(64,"0"),"hex"));
const integer=b=>BigInt("0x"+hex(b)), hash=b=>new Uint8Array(createHash("sha256").update(b).digest());
const tagged=(name,...parts)=>{const t=hash(Buffer.from(name));return hash(Buffer.concat([t,t,...parts]));};
const N=curve.Point.Fn.ORDER;
const mod=x=>((x%N)+N)%N;
const power=(a,n)=>{let out=1n;for(;n;n>>=1n,a=mod(a*a))if(n&1n)out=mod(out*a);return out;};
const key=new Uint8Array(32).fill(0x11), pub=curve.getPublicKey(key),dest=curve.getPublicKey(new Uint8Array(32).fill(0x22));
const tx=new Transaction({version:2});
for(let i=0;i<2;i++)tx.addInput({txid:(i?"33":"22").repeat(32),index:0,sequence:0xfffffffd,witnessUtxo:{amount:100000n,script:p2wpkh(pub).script},sighashType:1});
tx.addOutput({amount:199000n,script:p2wpkh(dest).script});
const unsigned=tx.toPSBT(), psbtDigest=hash(unsigned), sessionId=new Uint8Array(32).fill(0xd2);
const slots=[0,1].map(i=>{
 const opening=curve.Point.BASE.multiply(0x1234n+BigInt(i)).toBytes(true),rho=new Uint8Array(32).fill(0xa0+i);
 return {inputIndex:i,sighashType:1,signerPubkey:pub,messageHash:tx.preimageWitnessV0(i,p2pkh(pub).script,1,100000n),commitment:tagged("s2c/ecdsa/data",rho),opening,rho};
});
function signature(digest,k) {
 const r=curve.Point.BASE.multiply(k).x%N;let s=mod(power(k,N-2n)*(integer(digest)+r*integer(key)));if(s>N/2n)s=N-s;
 return Uint8Array.from([...b32(r),...b32(s)]);
}
const scenarios={};
for(const bad of [false,true]) {
 const signed=Transaction.fromPSBT(unsigned);
 const signatures=slots.map((slot,i)=>{
   const k=bad?BigInt(7+i*4):mod(0x1234n+BigInt(i)+integer(tagged("s2c/ecdsa/point",slot.opening,slot.rho)));
   const compact=signature(slot.messageHash,k);
   if(!curve.verify(compact,slot.messageHash,pub,{prehash:false,lowS:true}))throw Error("Fixture ECDSA failed");
   const der=curve.Signature.fromBytes(compact).toBytes("der");
   signed.updateInput(i,{partialSig:[[pub,Uint8Array.from([...der,1])]]});return compact;
 });
 const messages=[2,3,4].map(stage=>{
   const stageSlots=slots.map((slot,i)=>{const {rho,...base}=slot;return stage===2?{...base,rho:null,signature:null}:stage===3?{...base,rho,signature:null}:{...base,rho:null,signature:signatures[i]};});
   const bytes=aexbEncodePackage({stage,network:1,sessionId,psbtDigest,slots:stageSlots,psbt:stage===3?unsigned:new Uint8Array()});
   return {stage,package_hex:hex(bytes),medium_ur_parts:hodlUrEncodeMessage("x-btc-anti-exfil",hodlCborBstr(bytes),{maxBytes:100})};
 });
 scenarios[bad?"nonce-substitution":"success"]={expected:bad?"OPENING_MISMATCH":"PASS",signed_psbt_base64:Buffer.from(signed.toPSBT()).toString("base64"),messages};
}
writeFileSync(new URL("../test/fixtures/aexb/camera-demo.json",import.meta.url),JSON.stringify({description:"Public fixed-key two-input P2WPKH demo with invented outpoints. The failure uses valid ECDSA signatures with small chosen nonces 7 and 11 instead of the committed S2C nonces. Dark Skippy-inspired nonce-substitution illustration, NOT full Schnorr seed exfiltration or recovery.",unsigned_psbt_base64:Buffer.from(unsigned).toString("base64"),signer_pubkey:hex(pub),message_hashes:slots.map(s=>hex(s.messageHash)),scenarios},null,2)+"\n");
