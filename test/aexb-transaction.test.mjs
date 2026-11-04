import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Transaction, p2wpkh, p2sh, p2wsh, p2ms, p2pkh, p2tr} from "@scure/btc-signer";
import {secp256k1 as noble} from "@noble/curves/secp256k1.js";
import {aexbDecode, aexbEncodePackage} from "../src/js/aexb.js";
import {AexbCapture} from "../src/js/aexb-capture.js";
import {verifyAexbTransaction} from "../src/js/aexb-transaction.js";
import {hashesReady, sha256} from "../src/js/hashes.js";
import {secp256k1Ready} from "../src/js/secp256k1.js";
import {psbtWasmReady} from "../src/js/psbt-wasm.js";
await Promise.all([hashesReady,secp256k1Ready,psbtWasmReady]);
const f=JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json",import.meta.url)));
const msg=stage=>aexbDecode(Buffer.from(f.scenarios.success.messages.find(m=>m.stage===stage).package_hex,"hex"));
test("public camera fixture signatures bind to the embedded PSBT",()=>{
 const result=verifyAexbTransaction(msg(3),msg(4));assert.equal(result.ok,true);assert.equal(result.checkedSlots,2);
});
for(const change of ["amount","output","sequence","locktime","inputIndex","messageHash","pubkey","signature","sighash","missingUtxo"])
 test("embedded PSBT check rejects "+change,()=>{
  const reveal=msg(3), signatures=msg(4), tx=Transaction.fromPSBT(reveal.psbt);
  if(change==="amount")tx.updateInput(0,{witnessUtxo:{...tx.getInput(0).witnessUtxo,amount:99999n}});
  if(change==="output")tx.updateOutput(0,{amount:198999n});
  if(change==="sequence")tx.updateInput(0,{sequence:1});
  if(change==="locktime") { const altered=new Transaction({lockTime:1});for(let i=0;i<tx.inputsLength;i++)altered.addInput(tx.getInput(i));for(let i=0;i<tx.outputsLength;i++)altered.addOutput(tx.getOutput(i));reveal.psbt=altered.toPSBT(); }
  else reveal.psbt=tx.toPSBT();
  if(change==="inputIndex")signatures.slots[0].inputIndex=5;
  if(change==="messageHash")signatures.slots[0].messageHash[0]^=1;
  if(change==="pubkey")signatures.slots[0].signerPubkey=noble.getPublicKey(new Uint8Array(32).fill(3));
  if(change==="signature")signatures.slots[0].signature[1]^=1;
  if(change==="sighash")signatures.slots[0].sighashType=2;
  if(change==="missingUtxo") { const empty=new Transaction();empty.addInput({txid:'22'.repeat(32),index:0});empty.addOutput({script:p2wpkh(noble.getPublicKey(new Uint8Array(32).fill(1))).script,amount:100n});reveal.psbt=empty.toPSBT(); }
  reveal.psbtDigest=sha256(reveal.psbt);signatures.psbtDigest=reveal.psbtDigest.slice();
  assert.equal(verifyAexbTransaction(reveal,signatures).ok,false);
 });
for(const kind of ['native','wrapped','multisig','wrapped-multisig'])test('independent BIP143 signing fixture: '+kind,()=>{
 const key=new Uint8Array(32).fill(9),pub=noble.getPublicKey(key),other=noble.getPublicKey(new Uint8Array(32).fill(8));
 const multi=kind.includes('multisig'),witness=multi?p2ms(1,[pub,other]):null;
 const inner=multi?p2wsh(witness):p2wpkh(pub),payment=kind.startsWith('wrapped')?p2sh(inner):inner;
 const tx=new Transaction();tx.addInput({txid:'44'.repeat(32),index:0,witnessUtxo:{script:payment.script,amount:100000n},...(multi?{witnessScript:witness.script}:{}),...(kind.startsWith('wrapped')?{redeemScript:inner.script}:{})});tx.addOutput({script:p2wpkh(other).script,amount:99000n});
 const digest=tx.preimageWitnessV0(0,multi?witness.script:p2pkh(pub).script,1,100000n),psbt=tx.toPSBT(),psbtDigest=sha256(psbt);
 const sig={psbtDigest,slots:[{inputIndex:0,sighashType:1,signerPubkey:pub,messageHash:digest,signature:noble.sign(digest,key,{prehash:false,lowS:true})}]};
 assert.equal(verifyAexbTransaction({psbt,psbtDigest},sig).ok,true);
});

test("valid transcript math with a substituted PSBT is blocked by the combined observer",()=>{
 const messages=[2,3,4].map(msg),tx=Transaction.fromPSBT(messages[1].psbt);
 tx.updateOutput(0,{amount:198000n});messages[1].psbt=tx.toPSBT();
 const digest=sha256(messages[1].psbt);
 for(const m of messages)m.psbtDigest=digest.slice();
 const capture=new AexbCapture();for(const m of messages)capture.accept(aexbEncodePackage(m));
 assert.equal(capture.snapshot().verdict.ok,true);
 assert.deepEqual(capture.checkTransaction(),{ok:false,reason:"TRANSACTION_MESSAGE_HASH_MISMATCH",checkedSlots:0});
 capture.clear();assert.equal(capture.checkTransaction(),null);
});

// Every input context must be v1-supported; a missing slot never exempts it.
function partialFixture(kind) {
 const key=new Uint8Array(32).fill(9),pub=noble.getPublicKey(key),other=noble.getPublicKey(new Uint8Array(32).fill(8));
 const tx=new Transaction({allowUnknownInputs:true});
 tx.addInput({txid:'11'.repeat(32),index:0,witnessUtxo:{script:p2wpkh(pub).script,amount:100000n}});
 const multi=p2ms(1,[pub,other]),inner=kind.includes('multisig')?p2wsh(multi):p2wpkh(other);
 const payment=kind.startsWith('wrapped')?p2sh(inner):inner;
 const second={txid:'22'.repeat(32),index:0,witnessUtxo:{script:payment.script,amount:50000n}};
 if(kind.startsWith('wrapped'))second.redeemScript=inner.script;
 if(kind.includes('multisig'))second.witnessScript=multi.script;
 if(kind==='taproot'||kind==='tap-metadata')second.witnessUtxo.script=p2tr(other.slice(1)).script;
 if(kind==='tap-metadata')second.tapInternalKey=other.slice(1);
 if(kind==='legacy')second.witnessUtxo.script=p2pkh(other).script;
 if(kind==='missing-utxo')delete second.witnessUtxo;
 if(kind==='sighash')second.sighashType=3;
 tx.addOutput({script:p2wpkh(other).script,amount:149000n});tx.addInput(second);
 if(kind==='finalized'){tx.signIdx(new Uint8Array(32).fill(8),1);tx.finalizeIdx(1);}
 const psbt=tx.toPSBT(),psbtDigest=sha256(psbt),digest=tx.preimageWitnessV0(0,p2pkh(pub).script,1,100000n);
 return [{psbt,psbtDigest},{psbtDigest,slots:[{inputIndex:0,sighashType:1,signerPubkey:pub,messageHash:digest,signature:noble.sign(digest,key,{prehash:false,lowS:true})}]}];
}
for(const [kind,reason] of [['taproot','TRANSACTION_CONTEXT_UNSUPPORTED'],['tap-metadata','TRANSACTION_CONTEXT_UNSUPPORTED'],['legacy','TRANSACTION_INVALID'],['missing-utxo','TRANSACTION_CONTEXT_UNSUPPORTED'],['sighash','TRANSACTION_SIGHASH_UNSUPPORTED'],['finalized','TRANSACTION_ALREADY_FINALIZED']])test('non-slot input rejected: '+kind,()=>{
 assert.deepEqual(verifyAexbTransaction(...partialFixture(kind)),{ok:false,reason,checkedSlots:0});
});
for(const kind of ['native','wrapped','multisig','wrapped-multisig'])test('supported non-slot context accepted with explicit partial coverage: '+kind,()=>{
 assert.deepEqual(verifyAexbTransaction(...partialFixture(kind)),{ok:true,reason:null,checkedSlots:1,totalInputs:2,checkedInputs:[0]});
});

// v1 permits P2WSH only for standard multisig, not a P2PKH witness script.
for(const wrapped of [false,true])for(const supplied of [false,true])test(`reject key-hash script inside ${wrapped?'wrapped ':''}P2WSH, slot=${supplied}`,()=>{
 const key=new Uint8Array(32).fill(9),pub=noble.getPublicKey(key),witness=p2pkh(pub),inner=p2wsh(witness),payment=wrapped?p2sh(inner):inner;
 const tx=new Transaction();
 tx.addInput({txid:'11'.repeat(32),index:0,witnessUtxo:{script:p2wpkh(pub).script,amount:100000n}});
 tx.addInput({txid:'22'.repeat(32),index:0,witnessUtxo:{script:payment.script,amount:50000n},witnessScript:witness.script,...(wrapped?{redeemScript:inner.script}:{})});
 tx.addOutput({script:p2wpkh(pub).script,amount:149000n});
 const index=supplied?1:0,digest=tx.preimageWitnessV0(index,witness.script,1,supplied?50000n:100000n),psbt=tx.toPSBT(),psbtDigest=sha256(psbt);
 const result=verifyAexbTransaction({psbt,psbtDigest},{psbtDigest,slots:[{inputIndex:index,sighashType:1,signerPubkey:pub,messageHash:digest,signature:noble.sign(digest,key,{prehash:false,lowS:true})}]});
 assert.deepEqual(result,{ok:false,reason:'TRANSACTION_CONTEXT_UNSUPPORTED',checkedSlots:0});
});
