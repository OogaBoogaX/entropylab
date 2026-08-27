var vr=[16,20,24,28,32],Rc={0:"00",1:"01",2:"10",3:"11",4:"0",5:"1"};function kr(e){return e<=0?0:e*Math.log2(6)}function Br(e){let t=[],r="";for(let n of e)/\s|,|;|\|/.test(n)||(n>="1"&&n<="6"?t.push(n):r+=n);return{rolls:t,leftover:r}}function mi(e,t){let r=0;for(let n of e)r=r*4+(n-1);return r=r*2+t,Ae[r]}function Sr(e,t=24){let r=t===12?11:23,n=[],o=0,i="",s=0,c=[],a=[],f=[];for(let l of e){if(/\s|,|;|\|/.test(l))continue;let u=l.toLowerCase(),p=u>="1"&&u<="6",b=u==="h"||u==="t";if(!p&&!b){i+=l;continue}if(n.length>=r){s+=1;continue}if(c.length<5){if(b){i+=l;continue}let E=Number(u);if(E>=5){o+=1;continue}c.push(E);continue}let w;u==="h"||u==="1"||u==="2"||u==="3"?w=0:w=1,n.push(mi(c,w)),c=[]}let d=n.length>=r?"last-word":c.length===5?"coin":"dice",h=n.length*11;return a.push(`BitBox diceware: ${n.length} of ${r} lookup-table words (${h} bits). Then pick the checksum word.`),o>0&&a.push(`Skipped ${o} face${o===1?"":"s"} of 5 or 6 on the first five dice of a word (BitBox reroll).`),s>0&&f.push("Extra rolls after the last lookup-table word are ignored. The checksum word is a pick, not another roll."),i.length>0&&f.push(`Ignored characters: ${JSON.stringify(i.slice(0,24))}`),{words:n,targetWords:t,neededPartial:r,skippedHigh:o,leftover:i,extraAfter:s,waiting:d,diceInWord:c.length,bits:h,notes:a,warnings:f}}function $n(e,t){if(t==="bitbox")return{ok:!1,error:"BitBox diceware is not a hash of the digit string. Stay in BitBox-style mode and pick the checksum word after 23 lookup-table words.",notes:[],warnings:[]};let r=[],n=[],{rolls:o,leftover:i}=Br(e);if(i.length>0)return{ok:!1,error:`Dice must be faces 1\u20136. Ignored characters: ${JSON.stringify(i.slice(0,24))}`,notes:r,warnings:n};if(o.length===0)return{ok:!1,error:"Enter at least one dice roll (faces 1\u20136).",notes:r,warnings:n};let s=kr(o.length);if(r.push(`${o.length} rolls of a fair six-sided die \u2248 ${s.toFixed(1)} bits.`),t==="coldcard"){let a=new TextEncoder().encode(o.join("")),f=Z(a);return o.length<50?n.push("Fewer than 50 rolls. They still hash to 24 words, but real entropy is under 128 bits. Use 99 rolls for a full 256-bit 24-word seed."):o.length<99&&n.push("Fewer than 99 rolls. You have at least 128 bits; 99 rolls is the full 256-bit target."),r.push("Hash the rolls: SHA-256 of the digit string. Same math Coldcard shows on its dice check."),{ok:!0,bytes:f,hex:M.encode(f),bits:256,sourceBits:s,method:"coldcard-sha256",notes:r,warnings:n}}let c=o.map(a=>a==="6"?"0":a).map(a=>Rc[a]??"").join("");return r.push("Ian Coleman-style: each face is mapped through a prefix-free bit table (6 becomes 0). This is not the same as hashing the rolls."),xi(c,s,"coleman-dice",r,n)}function In(e){let t=[],r=[],n=e.replace(/\s|_/g,"").replace(/^0x/i,"").toLowerCase();if(!n)return{ok:!1,error:"Paste hexadecimal entropy (0-9, a-f).",notes:t,warnings:r};if(!/^[0-9a-f]+$/.test(n))return{ok:!1,error:"Hex entropy may only contain 0-9 and a-f.",notes:t,warnings:r};if(n.length%2!==0)return{ok:!1,error:"Hex entropy must have an even number of characters (whole bytes).",notes:t,warnings:r};let o=M.decode(n),i=o.length*8;t.push(`${o.length} bytes = ${i} bits of hex entropy.`);let s=Uc(o,t,r);return s.ok?{ok:!0,bytes:s.bytes,hex:M.encode(s.bytes),bits:s.bytes.length*8,sourceBits:i,method:"hex",notes:t,warnings:r}:s}function On(e){let t=[],r=[],n=e.replace(/\s/g,"");return n?/^[01]+$/.test(n)?(t.push(`${n.length} coin-flip bits.`),xi(n,n.length,"binary",t,r)):{ok:!1,error:"Binary entropy may only contain 0 and 1.",notes:t,warnings:r}:{ok:!1,error:"Enter a string of 0s and 1s.",notes:t,warnings:r}}function _n(e){return bi(e,Ae)}function Rn(e){return e.trim().toLowerCase().replace(/[^a-z\s]/g," ").split(/\s+/).filter(Boolean).join(" ")}function Mt(e){let t=Rn(e).split(" ").filter(Boolean),r=t.map((o,i)=>({index:i,word:o})).filter(({word:o})=>!Ae.includes(o));if(t.length===0)return{ok:!1,words:t,error:"Type or paste your seed phrase.",unknown:r};if(![12,15,18,21,24].includes(t.length))return{ok:!1,words:t,unknown:r,error:`A seed phrase is 12, 15, 18, 21, or 24 words. You entered ${t.length}.`};if(r.length>0)return{ok:!1,words:t,unknown:r,error:`Word ${r[0].index+1} (\u201C${r[0].word}\u201D) is not on the BIP39 English list.`};let n=t.join(" ");return Pn(n,Ae)?{ok:!0,words:t,unknown:r}:{ok:!1,words:t,unknown:r,error:"Words are on the list, but the checksum does not match. One of the words is wrong, or this is not a BIP39 phrase."}}function Tr(e){let t=Rn(e).split(" ").filter(Boolean),n={11:12,14:15,17:18,20:21,23:24}[t.length];if(!n)return null;let o=t.filter(s=>!Ae.includes(s));if(o.length>0)return{partialCount:t.length,completeCount:n,candidates:[],error:`\u201C${o[0]}\u201D is not on the BIP39 English list.`};let i=[];for(let s of Ae)Pn([...t,s].join(" "),Ae)&&i.push(s);return{partialCount:t.length,completeCount:n,candidates:i}}function xi(e,t,r,n,o){let s=vr.map(d=>d*8).filter(d=>d<=e.length).pop();if(!s)return{ok:!1,error:`Need at least 128 bits for a 12-word seed. This input is ${e.length} bits.`,notes:n,warnings:o};e.length>s&&o.push(`Using the first ${s} bits of ${e.length}. Extra bits are not mixed in.`);let c=e.slice(0,s),a=new Uint8Array(s/8);for(let d=0;d<a.length;d++)a[d]=Number.parseInt(c.slice(d*8,d*8+8),2);n.push(`BIP39 entropy length: ${s} bits \u2192 ${s/32+s/11} wait`);let f=s/32*3;return n[n.length-1]=`BIP39 entropy length: ${s} bits \u2192 ${f}-word seed.`,{ok:!0,bytes:a,hex:M.encode(a),bits:s,sourceBits:t,method:r,notes:n,warnings:o}}function Uc(e,t,r){let n=e.length;if(vr.includes(n))return{ok:!0,bytes:e,hex:M.encode(e),bits:n*8,sourceBits:n*8,method:"hex",notes:t,warnings:r};let o=[...vr].filter(s=>s<e.length).pop();if(!o)return{ok:!1,error:`Need 16, 20, 24, 28, or 32 bytes of entropy (128\u2013256 bits). Got ${e.length} bytes.`,notes:t,warnings:r};r.push(`Took the first ${o} bytes (${o*8} bits) of ${e.length}. Extra bytes were not mixed in.`);let i=e.slice(0,o);return{ok:!0,bytes:i,hex:M.encode(i),bits:o*8,sourceBits:e.length*8,method:"hex",notes:t,warnings:r}}function Pr(e,t,r=()=>{}){if(!Array.isArray(e))throw new TypeError(`"${t}" expected array, got type=${typeof e}`);for(let n=0;n<e.length;n++)r(e[n],`${t}[${n}]`);return e}var O=(e,t,r)=>K(e,t,r),Un=V;function vi(e,t=""){if(typeof e!="string"){let r=t&&`"${t}" `;throw new TypeError(r+"expected string, got type="+typeof e)}return e}function je(e,t="object"){if(e===null||typeof e!="object"||Array.isArray(e))throw new TypeError(t==="object"?"expected valid options object":`"${t}" expected object, got type=${typeof e}`);return e}function rt(e,t){if(typeof e!="function")throw new TypeError(`"${t}" is invalid: expected function, got ${typeof e}`);return e}var Ln=gr,he=(...e)=>Qe(...e),$r=e=>hn(e),pt=hr,Ir=e=>ht(e),Ar=BigInt(0),Ei=BigInt(1),Lc=e=>e?`"${e}" `:"";function Pe(e,t=""){if(typeof e!="boolean")throw new TypeError(Lc(t)+"expected boolean, got type="+typeof e);return e}function Or(e){if(typeof e=="bigint"){if(!Ke(e))throw new RangeError("positive bigint expected, got "+e)}else Un(e);return e}function gt(e,t=""){if(typeof e!="number"){let r=t&&`"${t}" `;throw new TypeError(r+"expected number, got type="+typeof e)}if(!Number.isSafeInteger(e)){let r=t&&`"${t}" `;throw new RangeError(r+"expected safe integer, got "+e)}}function zt(e){let t=Or(e).toString(16);return t.length&1?"0"+t:t}function ki(e){if(typeof e!="string")throw new TypeError("hex string expected, got "+typeof e);return e===""?Ar:BigInt("0x"+e)}function te(e){return ki(gr(e))}function Cn(e){return ki(gr(Cc(K(e)).reverse()))}function Dt(e,t){if(V(t),t===0)throw new Error("zero output length is invalid");e=Or(e);let r=t*2,n=e.toString(16);if(n.length>r)throw new RangeError("number is too large");return hn(n.padStart(r,"0"))}function Hn(e,t){return Dt(e,t).reverse()}function Cc(e){return Uint8Array.from(O(e))}function Bi(e){if(typeof e!="string")throw new TypeError("ascii string expected, got "+typeof e);return Uint8Array.from(e,(t,r)=>{let n=t.charCodeAt(0);if(t.length!==1||n>127)throw new RangeError(`string contains non-ASCII character "${e[r]}" with code ${n} at position ${r}`);return n})}function Ke(e){return typeof e=="bigint"&&Ar<=e}function Nn(e,t,r){return Ke(e)&&Ke(t)&&Ke(r)&&t<=e&&e<r}function Fn(e,t,r,n){if(!Nn(t,r,n))throw new RangeError("expected valid "+e+": "+r+" <= n < "+n+", got "+t)}function yt(e){if(e<Ar)throw new Error("expected non-negative bigint, got "+e);return e===Ar?0:e.toString(2).length}var jt=e=>(gt(e,"n"),(Ei<<BigInt(e))-Ei);function Si(e,t,r){if(V(e,"hashLen"),V(t,"qByteLen"),typeof r!="function")throw new TypeError("hmacFn must be a function");let n=w=>new Uint8Array(w),o=Uint8Array.of(),i=Uint8Array.of(0),s=Uint8Array.of(1),c=1e3,a=n(e),f=n(e),d=0,h=()=>{a.fill(1),f.fill(0),d=0},l=(...w)=>r(f,he(a,...w)),u=(w=o)=>{f=l(i,w),a=l(),w.length!==0&&(f=l(s,w),a=l())},p=()=>{if(d++>=c)throw new Error("drbg: tried max amount of iterations");let w=0,E=[];for(;w<t;){a=l();let A=a.slice();E.push(A),w+=a.length}return he(...E)};return(w,E)=>{h(),u(w);let A;for(;(A=E(p()))===void 0;)u();return h(),A}}function me(e,t={},r={},n="object"){je(e,n),je(t,"fields"),je(r,"optFields");function o(s,c,a){let f=n==="object"?`param "${String(s)}"`:`"${n}.${String(s)}"`,d=e[s];if(!Object.hasOwn(e,s)&&(a?d!==void 0:c!=="function"))throw new TypeError(`${f} is invalid: expected own property`);if(a&&d===void 0)return;let h=typeof d;if(h!==c||d===null)throw new TypeError(`${f} is invalid: expected ${c}, got ${h}`)}let i=(s,c)=>Object.entries(s).forEach(([a,f])=>o(a,f,c));i(t,!1),i(r,!0)}var Y=BigInt(0),L=BigInt(1),We=BigInt(2),$i=BigInt(3),Mn=BigInt(4),Ii=BigInt(5),Hc=BigInt(7),Oi=BigInt(8),Nc=BigInt(9),Fc=BigInt(15),_i=BigInt(16),Mc=BigInt("0x10000000000000000");function ae(e,t){if(t<=Y)throw new Error("mod: expected positive modulus, got "+t);let r=e%t;return r>=Y?r:t+r}function Ri(e,t,r){if(r<=L)throw new Error("pow: expected modulus > 1, got "+r);if(typeof t!="bigint")throw new TypeError("invalid exponent: expected bigint, got "+typeof t);if(t<Y)throw new Error("invalid exponent, negatives unsupported");if(t===Y)return L;if(t===L)return e;let n=e%r;if(n<Y&&(n+=r),t<Mc){let c=L;for(;t>Y;)t&L&&(c=c*n%r),n=n*n%r,t>>=L;return c}let o=[];for(;t>Y;)o.push(Number(t&Fc)),t>>=Mn;let i=new Array(16);i[0]=L,i[1]=n;for(let c=2;c<16;c++)i[c]=i[c-1]*n%r;let s=i[o[o.length-1]];for(let c=o.length-2;c>=0;c--){s=s*s%r,s=s*s%r,s=s*s%r,s=s*s%r;let a=o[c];a!==0&&(s=s*i[a]%r)}return s}function fe(e,t,r){if(r<=L)throw new Error("pow2: expected modulus > 1, got "+r);if(t<Y)throw new Error("pow2: expected non-negative exponent, got "+t);let n=e;for(;t-- >Y;)n*=n,n%=r;return n}function Ti(e,t){if(e===Y)throw new Error("invert: expected non-zero number");if(t<=L)throw new Error("invert: expected modulus > 1, got "+t);let r=ae(e,t),n=t,o=Y,i=L;for(;r!==Y;){let c=n/r,a=n-r*c,f=o-i*c;n=r,r=a,o=i,i=f}if(n!==L)throw new Error("invert: does not exist");return ae(o,t)}function Ui(e,t){if(t<=L)throw new Error("invertCt: expected prime modulus > 1, got "+t);let r=ae(e,t);if(r===Y)throw new Error("invertCt: expected non-zero number");let n=Ri(r,t-We,t);if(ae(r*n,t)!==L)throw new Error("invertCt: does not exist");return n}function zn(e,t,r){let n=e;if(!n.eql(n.sqr(t),r))throw new Error("Cannot find square root")}function Dn(e,t){if((e&L)===Y)throw new Error(t+": expected odd modulus, got "+e)}function Li(e,t){let r=e,n=(r.ORDER+L)/Mn,o=r.pow(t,n);return zn(r,o,t),o}function zc(e,t){let r=e,n=(r.ORDER-Ii)/Oi,o=r.mul(t,We),i=r.pow(o,n),s=r.mul(t,i),c=r.mul(r.mul(s,We),i),a=r.mul(s,r.sub(c,r.ONE));return zn(r,a,t),a}function Dc(e){let t=wt(e),r=Ci(e),n=r(t,t.neg(t.ONE)),o=r(t,n),i=r(t,t.neg(n)),s=(e+Hc)/_i;return((c,a)=>{let f=c,d=f.pow(a,s),h=f.mul(d,n),l=f.mul(d,o),u=f.mul(d,i),p=f.eql(f.sqr(h),a),b=f.eql(f.sqr(l),a);d=f.cmov(d,h,p),h=f.cmov(u,l,b);let w=f.eql(f.sqr(h),a),E=f.cmov(d,h,w);return zn(f,E,a),E})}function Ci(e){if(e<$i)throw new Error("sqrt is not defined for small field");Dn(e,"tonelliShanks");let t=e-L,r=0;for(;t%We===Y;)t/=We,r++;let n=We,o=wt(e);for(;Ai(o,n)===1;)if(n++>1e3)throw new Error("Cannot find square root: probably non-prime P");if(r===1)return Li;let i=o.pow(n,t),s=(t+L)/We;return function(a,f){let d=a;if(d.is0(f))return f;if(Ai(d,f)!==1)throw new Error("Cannot find square root");let h=r,l=d.mul(d.ONE,i),u=d.pow(f,t),p=d.pow(f,s);for(;!d.eql(u,d.ONE);){if(d.is0(u))throw new Error("Cannot find square root: probably non-prime P");let b=1,w=d.sqr(u);for(;!d.eql(w,d.ONE);)if(b++,w=d.sqr(w),b===h)throw new Error("Cannot find square root");let E=L<<BigInt(h-b-1),A=d.pow(l,E);h=b,l=d.sqr(A),u=d.mul(u,l),p=d.mul(p,A)}return p}}function jc(e){return Dn(e,"Fp.sqrt"),e%Mn===$i?Li:e%Oi===Ii?zc:e%_i===Nc?Dc(e):Ci(e)}var Kc=["create","isValid","is0","neg","inv","sqrt","sqr","eql","add","sub","mul","pow","div","addN","subN","mulN","sqrN"];function bt(e){if(je(e,"field"),typeof e.ORDER!="bigint")throw new TypeError('param "ORDER" is invalid: expected bigint, got '+typeof e.ORDER);gt(e.BYTES,"BYTES"),gt(e.BITS,"BITS");for(let t of Kc)rt(e[t],"field."+t);if(e.BYTES<1||e.BITS<1)throw new Error("invalid field: expected BYTES/BITS > 0");if(e.ORDER<=L)throw new Error("invalid field: expected ORDER > 1, got "+e.ORDER);return e}function jn(e,t,r=!1){bt(e),Pr(t,"nums"),Pe(r,"passZero");let n=e,o=new Array(t.length).fill(r?n.ZERO:void 0),i=t.reduce((c,a,f)=>n.is0(a)?c:(o[f]=c,n.mul(c,a)),n.ONE),s=n.inv(i);return t.reduceRight((c,a,f)=>n.is0(a)?c:(o[f]=n.mul(c,o[f]),n.mul(c,a)),s),o}function Ai(e,t){bt(e);let r=e;Dn(r.ORDER,"FpLegendre");let n=(r.ORDER-L)/We,o=r.pow(t,n),i=r.eql(o,r.ONE),s=r.eql(o,r.ZERO),c=r.eql(o,r.neg(r.ONE));if(!i&&!s&&!c)throw new Error("invalid Legendre symbol result");return i?1:s?0:-1}function Wc(e,t){if(t!==void 0&&Un(t),e<=Y)throw new Error("invalid n length: expected positive n, got "+e);if(t!==void 0&&t<1)throw new Error("invalid n length: expected positive bit length, got "+t);let r=yt(e);if(t!==void 0&&t<r)throw new Error(`invalid n length: expected nBitLength (${t}) >= bitLen(n) (${r})`);let n=t!==void 0?t:r,o=Math.ceil(n/8);return{nBitLength:n,nByteLength:o}}var Pi=new WeakMap,_r=class{constructor(t,r={}){g(this,"ORDER");g(this,"BITS");g(this,"BYTES");g(this,"isLE");g(this,"ZERO",Y);g(this,"ONE",L);g(this,"_lengths");g(this,"_mod");if(t<=L)throw new Error("invalid field: expected ORDER > 1, got "+t);let n;this.isLE=!1,r!=null&&typeof r=="object"&&(typeof r.BITS=="number"&&(n=r.BITS),typeof r.sqrt=="function"&&Object.defineProperty(this,"sqrt",{value:r.sqrt,enumerable:!0}),typeof r.isLE=="boolean"&&(this.isLE=r.isLE),r.allowedLengths&&(this._lengths=Object.freeze(r.allowedLengths.slice())),typeof r.modFromBytes=="boolean"&&(this._mod=r.modFromBytes));let{nBitLength:o,nByteLength:i}=Wc(t,n);if(i>2048)throw new Error("invalid field: expected ORDER of <= 2048 bytes");this.ORDER=t,this.BITS=o,this.BYTES=i,Object.freeze(this)}create(t){return ae(t,this.ORDER)}isValid(t){if(typeof t!="bigint")throw new TypeError("invalid field element: expected bigint, got "+typeof t);return Y<=t&&t<this.ORDER}is0(t){return t===Y}isValidNot0(t){return!this.is0(t)&&this.isValid(t)}isOdd(t){return(t&L)===L}neg(t){return ae(-t,this.ORDER)}eql(t,r){return t===r}sqr(t){return ae(t*t,this.ORDER)}add(t,r){return ae(t+r,this.ORDER)}sub(t,r){return ae(t-r,this.ORDER)}mul(t,r){return ae(t*r,this.ORDER)}pow(t,r){return Ri(t,r,this.ORDER)}div(t,r){return ae(t*Ti(r,this.ORDER),this.ORDER)}sqrN(t){return t*t}addN(t,r){return t+r}subN(t,r){return t-r}mulN(t,r){return t*r}inv(t){return Ti(t,this.ORDER)}sqrt(t){let r=Pi.get(this);return r||Pi.set(this,r=jc(this.ORDER)),r(this,t)}toBytes(t){return this.isLE?Hn(t,this.BYTES):Dt(t,this.BYTES)}fromBytes(t,r=!1){O(t);let{_lengths:n,BYTES:o,isLE:i,ORDER:s,_mod:c}=this;if(n){if(t.length<1||!n.includes(t.length)||t.length>o)throw new Error("Field.fromBytes: expected "+n+" bytes, got "+t.length);let f=new Uint8Array(o);f.set(t,i?0:f.length-t.length),t=f}if(t.length!==o)throw new Error("Field.fromBytes: expected "+o+" bytes, got "+t.length);let a=i?Cn(t):te(t);if(c&&(a=ae(a,s)),!r&&!this.isValid(a))throw new Error("invalid field element: outside of range 0..ORDER");return a}invertBatch(t){return jn(this,t,!0)}cmov(t,r,n){return Pe(n,"condition"),n?r:t}};function wt(e,t={}){return Object.freeze(_r.prototype),new _r(e,t)}function Hi(e){if(typeof e!="bigint")throw new Error("field order must be bigint");if(e<=L)throw new Error("field order must be greater than 1");let t=yt(e-L);return Math.ceil(t/8)}function Rr(e){let t=Hi(e);return t+Math.ceil(t/2)}function Kt(e,t,r=!1){O(e);let n=e.length,o=Hi(t),i=Math.max(Rr(t),16);if(n<i||n>1024)throw new Error("expected "+i+"-1024 bytes of input, got "+n);let s=r?Cn(e):te(e),c=ae(s,t-L)+L;return r?Hn(c,o):Dt(c,o)}var qn=BigInt(0),Wt=BigInt(1),qc=BigInt(4),Kn=16,Ni=128,Vc=5,Fi=2**31;function mt(e){let t=e;if(typeof t!="function")throw new TypeError('"Point" expected constructor, got type='+typeof e);rt(t.fromAffine,"Point.fromAffine"),rt(t.fromBytes,"Point.fromBytes"),rt(t.fromHex,"Point.fromHex"),je(t.BASE,"Point.BASE"),je(t.ZERO,"Point.ZERO"),bt(t.Fp),bt(t.Fn)}function zi(e,t){mt(e),Di(t,e);let r=jn(e.Fp,t.map(n=>n.Z));return t.map((n,o)=>e.fromAffine(n.toAffine(r[o])))}function Yc(e,t,r=1){if(!Number.isSafeInteger(e)||e<r||e>t)throw new Error("invalid window size, expected ["+r+".."+t+"], got W="+e)}function Gc(e,t){let r=e*(4*t+128);if(r>Fi)throw new Error("invalid window size: table would need ~"+Math.ceil(r/2**20)+" MiB, max "+Fi/2**20+" MiB")}function Vn(e,t){if(e!==void 0){rt(e,"randomBytes");try{let r=e(t);if(!pt(r)||r.length!==t)return}catch{return}return e}}function Di(e,t){Pr(e,"points"),e.forEach((r,n)=>{if(!(r instanceof t))throw new Error("invalid point at index "+n)})}function Xc(e,t,r){if(!Array.isArray(e))throw new Error("array of scalars expected");e.forEach((n,o)=>{if(!(r===void 0?t.isValid(n):Ke(n)&&n<r))throw new Error("invalid scalar at index "+o)})}var ji=new WeakMap;function Wn(e){return ji.get(e)||1}function Zc(e,t){let r=e.double(),n=[e];for(let o=1;o<t;o++)n.push(n[o-1].add(r));return n}function Qc(e,t){let r=2**t,n=r/2,o=BigInt(r-1),i=[];for(;e>qn;){let s=0;e&Wt&&(s=Number(e&o),s>=n&&(s-=r),e-=BigInt(s)),i.push(s),e>>=Wt}return i}function Jc(e,t,r){let n=2**t,o=n/2,i=BigInt(n-1),s=BigInt(t),c=[];for(let a=0;a<r;a++){let f=Number(e&i);e>>=s,f>o&&(f-=n,e+=Wt),c.push(f)}if(e!==qn)throw new Error("invalid wnaf");return c}function ea(e,t,r){let n=0;for(let i of r)n=Math.max(n,i.length);let o=e;for(let i=n-1;i>=0;i--){i!==n-1&&(o=o.double());for(let s=0;s<r.length;s++){let c=r[s][i];if(c){let a=t[s][Math.abs(c)-1>>1];o=o.add(c<0?a.negate():a)}}}return o}var Ur=class{constructor(t,r){g(this,"Point");g(this,"BASE");g(this,"ZERO");g(this,"randomBytes");g(this,"wnafPrecomputes",new WeakMap);g(this,"baseCanBeBlinded");g(this,"bits");mt(t),this.randomBytes=Vn(r,Kn),this.Point=t,this.BASE=t.BASE,this.ZERO=t.ZERO,this.bits=t.Fn.BITS}buildWnafTable(t,r,n){let o=Math.ceil(n/r)+1,i=2**(r-1),s=[],c=t;for(let a=0;a<o;a++){let f=c;for(let d=0;d<i;d++)s.push(f),f=f.add(c);c=s[s.length-1].double()}return{W:r,bits:n,windows:o,comp:s}}wnafCachedCT(t,r){let{W:n,windows:o,comp:i}=t,s=2**(n-1),c=Jc(r,n,o),a=this.ZERO,f=this.BASE;for(let d=0;d<o;d++){let h=c[d],l=d*s,u=Math.abs(h)-1,p=i[l];for(let w=1;w<s;w++)p=w===u?i[l+w]:p;let b=p.negate();h===0?f=f.add(i[l]):a=a.add(h<0?b:p)}return{p:a,f}}getWnafPrecomputes(t,r,n,o){let i=this.wnafPrecomputes.get(r),s=i?.find(c=>c.W===t&&c.bits===n);return s||(s=this.buildWnafTable(r,t,n),typeof o=="function"&&(s={...s,comp:o(s.comp)}),i||(i=[],this.wnafPrecomputes.set(r,i)),i.push(s)),s}assertPoint(t){if(!(t instanceof this.Point))throw new TypeError('"point" expected Point instance, got type='+typeof t)}validateMulInput(t,r){if(this.assertPoint(t),!Nn(r,Wt,this.Point.Fn.ORDER))throw new Error("invalid scalar")}runCT(t,r,n,o){let i=Wn(t);return i===1?this.fixedWindowCT(t,r,n):this.wnafCachedCT(this.getWnafPrecomputes(i,t,n,o),r)}mulCT(t,r,n){return this.validateMulInput(t,r),this.runCT(t,r,this.bits,n)}mulCTBlinded(t,r,n){if(this.validateMulInput(t,r),this.randomBytes===void 0)throw new Error("randomBytes is required for scalar blinding");let o=this.Point.Fn.BITS+Ni,i=this.randomBytes(Kn);if(!pt(i)||i.length!==Kn)throw new Error("randomBytes returned invalid byte array");i[0]=i[0]&63|128;let s=r+te(i)*this.Point.Fn.ORDER;return this.runCT(t,s,o,n)}fixedWindowCT(t,r,n){let o=Vc,i=1<<o,s=jt(o),c=new Array(i);c[0]=this.ZERO;for(let d=1;d<i;d++)c[d]=c[d-1].add(t);let a=Math.ceil(n/o),f=this.ZERO;for(let d=a-1;d>=0;d--){if(d!==a-1)for(let u=0;u<o;u++)f=f.double();let h=Number(r>>BigInt(d*o)&s),l=c[0];for(let u=1;u<i;u++)l=u===h?c[u]:l;f=f.add(l)}return{p:f,f}}shouldBlind(t,r){return this.randomBytes===void 0?!1:r===Wt?!0:t!==this.BASE?!1:(this.baseCanBeBlinded===void 0&&(this.baseCanBeBlinded=this.mulUnsafe(this.BASE,this.Point.Fn.ORDER).is0()),this.baseCanBeBlinded)}mulSecret(t,r,n,o){return this.shouldBlind(t,n)?this.mulCTBlinded(t,r,o):this.mulCT(t,r,o)}mulUnsafe(t,r,n){if(this.assertPoint(t),!Ke(r))throw new Error("invalid scalar");let o=Wn(t);if(o===1||r>=this.Point.Fn.ORDER)return Lr(this.Point,[t],[r],!0);let i=this.getWnafPrecomputes(o,t,this.bits,n);return this.wnafCachedCT(i,r).p}setWindowSize(t,r){this.assertPoint(t),Yc(r,this.bits);let n=Math.ceil((this.bits+Ni)/r)+1;Gc(n*2**(r-1),this.Point.Fp.BYTES),ji.set(t,r),this.wnafPrecomputes.delete(t)}hasWindowSize(t){return Wn(t)!==1}};function Lr(e,t,r,n=!1){if(mt(e),Di(t,e),Pe(n,"allowOversized"),Xc(r,e.Fn,n?e.Fn.ORDER**qc:void 0),t.length!==r.length)throw new Error("arrays of points and scalars must have equal length");let o=t.map(s=>Zc(s,4)),i=r.map(s=>Qc(s,4));return ea(e.ZERO,o,i)}function Mi(e,t,r){if(t){if(t.ORDER!==e)throw new Error("Field.ORDER must match order: Fp == p, Fn == n");return bt(t),t}else return wt(e,{isLE:r})}function Ki(e,t,r={},n){if(e!=="weierstrass"&&e!=="edwards")throw new Error('expected curve type "weierstrass" or "edwards"');if(n===void 0&&(n=e==="edwards"),!t||typeof t!="object")throw new Error(`expected valid ${e} CURVE object`);me(r);for(let a of["p","n","h"]){let f=t[a];if(!(Ke(f)&&f!==qn))throw new Error(`CURVE.${a} must be positive bigint`)}let o=Mi(t.p,r.Fp,n),i=Mi(t.n,r.Fn,n),c=["Gx","Gy","a",e==="weierstrass"?"b":"d"];for(let a of c)if(!o.isValid(t[a]))throw new Error(`CURVE.${a} must be valid field element of CURVE.Fp`);return t=Object.freeze(Object.assign({},t)),{CURVE:t,Fp:o,Fn:i}}function Cr(e,t){return function(n){let o=e(n);return{secretKey:o,publicKey:t(o)}}}var ta=BigInt(0),Yn=class extends Error{constructor(t=""){super(t)}},_e={Err:Yn,_tlv:{encode:(e,t)=>{let{Err:r}=_e;if(gt(e,"tag"),e<0||e>255)throw new r("tlv.encode: wrong tag");if(vi(t,"data"),t.length&1)throw new r("tlv.encode: unpadded data");let n=t.length/2,o=zt(n);if(o.length/2&128)throw new r("tlv.encode: long form length too big");let i=n>127?zt(o.length/2|128):"";return zt(e)+i+o+t},decode(e,t){let{Err:r}=_e;t=O(t,void 0,"DER data");let n=0;if(e<0||e>255)throw new r("tlv.decode: wrong tag");if(t.length<2||t[n++]!==e)throw new r("tlv.decode: wrong tlv");let o=t[n++],i=!!(o&128),s=0;if(!i)s=o;else{let a=o&127;if(!a)throw new r("tlv.decode(long): indefinite length not supported");if(a>4)throw new r("tlv.decode(long): byte length is too big");let f=t.subarray(n,n+a);if(f.length!==a)throw new r("tlv.decode: length bytes not complete");if(f[0]===0)throw new r("tlv.decode(long): zero leftmost byte");for(let d of f)s=s<<8|d;if(n+=a,s<128)throw new r("tlv.decode(long): not minimal encoding")}let c=t.subarray(n,n+s);if(c.length!==s)throw new r("tlv.decode: wrong value length");return{v:c,l:t.subarray(n+s)}}},_int:{encode(e){let{Err:t}=_e;if(Or(e),e<ta)throw new t("integer: negative integers are not allowed");let r=zt(e);if(Number.parseInt(r[0],16)&8&&(r="00"+r),r.length&1)throw new t("unexpected DER parsing assertion: unpadded hex");return r},decode(e){let{Err:t}=_e;if(e.length<1)throw new t("invalid signature integer: empty");if(e[0]&128)throw new t("invalid signature integer: negative");if(e.length>1&&e[0]===0&&!(e[1]&128))throw new t("invalid signature integer: unnecessary leading zero");return te(e)}},toSig(e){let{Err:t,_int:r,_tlv:n}=_e,o=O(e,void 0,"signature"),{v:i,l:s}=n.decode(48,o);if(s.length)throw new t("invalid signature: left bytes after parsing");let{v:c,l:a}=n.decode(2,i),{v:f,l:d}=n.decode(2,a);if(d.length)throw new t("invalid signature: left bytes after parsing");return{r:r.decode(c),s:r.decode(f)}},hexFromSig(e){let{_tlv:t,_int:r}=_e;me(e,{r:"bigint",s:"bigint"},{},"sig");let n=t.encode(2,r.encode(e.r)),o=t.encode(2,r.encode(e.s)),i=n+o;return t.encode(48,i)}},Gn=(Object.freeze(_e._tlv),Object.freeze(_e._int),Object.freeze(_e));var Wi=(e,t)=>(e+(e>=0?t:-t)/qi)/t;function ra(e,t,r){Fn("scalar",e,Re,r);let[[n,o],[i,s]]=t,c=Wi(s*e,r),a=Wi(-o*e,r),f=e-c*n-a*i,d=-c*o-a*s,h=f<Re,l=d<Re;h&&(f=-f),l&&(d=-d);let u=jt(Math.ceil(yt(r)/2))+nt;if(f<Re||f>=u||d<Re||d>=u)throw new Error("splitScalar (endomorphism): failed for k");return{k1neg:h,k1:f,k2neg:l,k2:d}}function Qn(e){if(!["compact","recovered","der"].includes(e))throw new Error('Signature format must be "compact", "recovered", or "der"');return e}function Xn(e,t){me(e);let r={};for(let n of Object.keys(t))r[n]=e[n]===void 0?t[n]:e[n];return Pe(r.lowS,"lowS"),Pe(r.prehash,"prehash"),r.format!==void 0&&Qn(r.format),r}var Re=BigInt(0),nt=BigInt(1),qi=BigInt(2),Zn=BigInt(3),na=BigInt(4);function Vi(e,t={}){let r=Ki("weierstrass",e,t),n=r.Fp,o=r.Fn,i=r.CURVE,{h:s,n:c}=i;me(t,{},{allowInfinityPoint:"boolean",clearCofactor:"function",isTorsionFree:"function",fromBytes:"function",toBytes:"function",endo:"object",randomBytes:"function"});let{endo:a,allowInfinityPoint:f}=t,d=t.randomBytes===void 0?Ir:t.randomBytes;if(a&&(!n.is0(i.a)||typeof a.beta!="bigint"||!Array.isArray(a.basises)))throw new Error('invalid endo: expected "beta": bigint and "basises": array');let h=Gi(n,o);function l(){if(!n.isOdd)throw new Error("compression is not supported: Field does not have .isOdd()")}function u(R,m,k){if(f&&m.is0())return Uint8Array.of(0);let{x:S,y:v}=m.toAffine(),y=n.toBytes(S);if(Pe(k,"isCompressed"),k){l();let x=!n.isOdd(v);return he(Yi(x),y)}else return he(Uint8Array.of(4),y,n.toBytes(v))}function p(R){O(R,void 0,"Point");let{publicKey:m,publicKeyUncompressed:k}=h,S=R.length,v=R[0],y=R.subarray(1);if(f&&S===1&&v===0)return{x:n.ZERO,y:n.ZERO};if(S===m&&(v===2||v===3)){let x=n.fromBytes(y);if(!n.isValid(x))throw new Error("bad point: is not on curve, wrong x");let B=C(x),T;try{T=n.sqrt(B)}catch(_){let z=_ instanceof Error?": "+_.message:"";throw new Error("bad point: is not on curve, sqrt error"+z)}l();let $=n.isOdd(T);return(v&1)===1!==$&&(T=n.neg(T)),{x,y:T}}else if(S===k&&v===4){let x=n.BYTES,B=n.fromBytes(y.subarray(0,x)),T=n.fromBytes(y.subarray(x,x*2));if(!P(B,T))throw new Error("bad point: is not on curve");return{x:B,y:T}}else throw new Error(`bad point: got length ${S}, expected compressed=${m} or uncompressed=${k}`)}let b=t.toBytes===void 0?u:t.toBytes,w=t.fromBytes===void 0?p:t.fromBytes,E=n.mul(i.b,Zn),A=n.is0(i.a)?R=>n.ZERO:R=>n.mul(i.a,R);function C(R){let m=n.sqr(R),k=n.mul(m,R);return n.add(n.add(k,n.mul(R,i.a)),i.b)}function P(R,m){let k=n.sqr(m),S=C(R);return n.eql(k,S)}if(!P(i.Gx,i.Gy))throw new Error("bad curve params: generator point");let J=n.mul(n.pow(i.a,Zn),na),N=n.mul(n.sqr(i.b),BigInt(27));if(n.is0(n.add(J,N)))throw new Error("bad curve params: a or b");function oe(R,m,k=!1){if(!n.isValid(m)||k&&n.is0(m))throw new Error(`bad point coordinate ${R}`);return m}function be(R){if(!(R instanceof X))throw new Error("Weierstrass Point expected")}function ie(R){if(!a||!a.basises)throw new Error("no endo");return ra(R,a.basises,o.ORDER)}function F(R,m,k,S){if(!o.isValid(S))throw new RangeError("invalid scalar: out of range");if(a){let{k1neg:v,k1:y,k2neg:x,k2:B}=ie(S),T=new X(n.mul(k.X,a.beta),k.Y,k.Z);R.push(v?k.negate():k,x?T.negate():T),m.push(y,B)}else R.push(k),m.push(S)}let ve=new WeakSet,U=class U{constructor(m,k,S){g(this,"X");g(this,"Y");g(this,"Z");this.X=oe("x",m),this.Y=oe("y",k,!0),this.Z=oe("z",S),Object.freeze(this)}static CURVE(){return i}static fromAffine(m){let{x:k,y:S}=m||{};if(!m||!n.isValid(k)||!n.isValid(S))throw new Error("invalid affine point");if(m instanceof U)throw new Error("projective point not allowed");return n.is0(k)&&n.is0(S)?U.ZERO:new U(k,S,n.ONE)}static fromBytes(m){let k=U.fromAffine(w(O(m,void 0,"point")));return k.assertValidity(),k}static fromHex(m){return U.fromBytes($r(m))}get x(){return this.toAffine().x}get y(){return this.toAffine().y}precompute(m=6,k=!0){return se.setWindowSize(this,m),k||this.multiply(Zn),this}assertValidity(){let m=this;if(m.is0()){if(t.allowInfinityPoint&&n.is0(m.X)&&n.eql(m.Y,n.ONE)&&n.is0(m.Z))return;throw new Error("bad point: ZERO")}if(ve.has(m))return;let{x:k,y:S}=m.toAffine();if(!n.isValid(k)||!n.isValid(S))throw new Error("bad point: x or y not field elements");if(!P(k,S))throw new Error("bad point: equation left != right");if(!m.isTorsionFree())throw new Error("bad point: not in prime-order subgroup");ve.add(m)}hasEvenY(){let{y:m}=this.toAffine();if(!n.isOdd)throw new Error("Field doesn't support isOdd");return!n.isOdd(m)}equals(m){be(m);let{X:k,Y:S,Z:v}=this,{X:y,Y:x,Z:B}=m,T=n.eql(n.mul(k,B),n.mul(y,v)),$=n.eql(n.mul(S,B),n.mul(x,v));return T&&$}negate(){return new U(this.X,n.neg(this.Y),this.Z)}double(){let{X:m,Y:k,Z:S}=this,v=n.ZERO,y=n.ZERO,x=n.ZERO,B=n.mul(m,m),T=n.mul(k,k),$=n.mul(S,S),I=n.mul(m,k);return I=n.add(I,I),x=n.mul(m,S),x=n.add(x,x),v=A(x),y=n.mul(E,$),y=n.add(v,y),v=n.sub(T,y),y=n.add(T,y),y=n.mul(v,y),v=n.mul(I,v),x=n.mul(E,x),$=A($),I=n.sub(B,$),I=A(I),I=n.add(I,x),x=n.add(B,B),B=n.add(x,B),B=n.add(B,$),B=n.mul(B,I),y=n.add(y,B),$=n.mul(k,S),$=n.add($,$),B=n.mul($,I),v=n.sub(v,B),x=n.mul($,T),x=n.add(x,x),x=n.add(x,x),new U(v,y,x)}add(m){be(m);let{X:k,Y:S,Z:v}=this,{X:y,Y:x,Z:B}=m,T=n.ZERO,$=n.ZERO,I=n.ZERO,_=n.mul(k,y),z=n.mul(S,x),q=n.mul(v,B),ce=n.add(k,S),D=n.add(y,x);ce=n.mul(ce,D),D=n.add(_,z),ce=n.sub(ce,D),D=n.add(k,v);let j=n.add(y,B);return D=n.mul(D,j),j=n.add(_,q),D=n.sub(D,j),j=n.add(S,v),T=n.add(x,B),j=n.mul(j,T),T=n.add(z,q),j=n.sub(j,T),I=A(D),T=n.mul(E,q),I=n.add(T,I),T=n.sub(z,I),I=n.add(z,I),$=n.mul(T,I),z=n.add(_,_),z=n.add(z,_),q=A(q),D=n.mul(E,D),z=n.add(z,q),q=n.sub(_,q),q=A(q),D=n.add(D,q),_=n.mul(z,D),$=n.add($,_),_=n.mul(j,D),T=n.mul(ce,T),T=n.sub(T,_),_=n.mul(ce,z),I=n.mul(j,I),I=n.add(I,_),new U(T,$,I)}subtract(m){return be(m),this.add(m.negate())}is0(){return this.equals(U.ZERO)}multiply(m){if(!o.isValidNot0(m))throw new RangeError("invalid scalar: out of range");let{p:k,f:S}=se.mulSecret(this,m,s,ke);return ke([k,S])[0]}multiplyUnsafe(m){let k=this,S=m;if(!o.isValid(S))throw new RangeError("invalid scalar: out of range");if(S===Re||k.is0())return U.ZERO;if(S===nt)return k;if(se.hasWindowSize(this))return se.mulUnsafe(k,S,ke);let v=[],y=[];return F(v,y,k,S),Lr(U,v,y)}mulAddUnsafe(m,k,S){be(k);let v=[],y=[];return F(v,y,this,m),F(v,y,k,S),Lr(U,v,y)}toAffine(m){let k=this,S=m;if(S!=null&&!n.isValid(S))throw new RangeError('"invertedZ" expected valid field element');let{X:v,Y:y,Z:x}=k;if(n.eql(x,n.ONE))return{x:v,y};let B=k.is0();S==null&&(S=B?n.ONE:n.inv(x));let T=n.mul(v,S),$=n.mul(y,S),I=n.mul(x,S);if(B)return{x:n.ZERO,y:n.ZERO};if(!n.eql(I,n.ONE))throw new Error("invZ was invalid");return{x:T,y:$}}isTorsionFree(){let{isTorsionFree:m}=t;return s===nt?!0:m?m(U,this):se.mulUnsafe(this,c).is0()}clearCofactor(){let{clearCofactor:m}=t;return s===nt?this:m?m(U,this):this.multiplyUnsafe(s)}isSmallOrder(){return s===nt?this.is0():this.clearCofactor().is0()}toBytes(m=!0){return Pe(m,"isCompressed"),this.assertValidity(),b(U,this,m)}toHex(m=!0){return Ln(this.toBytes(m))}toString(){return`<Point ${this.is0()?"ZERO":this.toHex()}>`}};g(U,"BASE",new U(i.Gx,i.Gy,n.ONE)),g(U,"ZERO",new U(n.ZERO,n.ONE,n.ZERO)),g(U,"Fp",n),g(U,"Fn",o);let X=U,ke=R=>zi(X,R),se=new Ur(X,d);return se.bits>=6&&X.BASE.precompute(6),Object.freeze(X.prototype),Object.freeze(X),X}function Yi(e){return Uint8Array.of(e?2:3)}function Gi(e,t){return{secretKey:t.BYTES,publicKey:1+e.BYTES,publicKeyUncompressed:1+2*e.BYTES,publicKeyHasPrefix:!0,signature:2*t.BYTES}}function oa(e,t={}){mt(e);let{Fn:r}=e,n=t.randomBytes===void 0?Ir:t.randomBytes,o=Object.assign(Gi(e.Fp,r),{seed:Math.max(Rr(r.ORDER),16)});function i(u){try{let p=r.fromBytes(u);return r.isValidNot0(p)}catch{return!1}}function s(u,p){let{publicKey:b,publicKeyUncompressed:w}=o;try{let E=u.length;return p===!0&&E!==b||p===!1&&E!==w?!1:!!e.fromBytes(u)}catch{return!1}}function c(u){return u=u===void 0?n(o.seed):u,Kt(O(u,o.seed,"seed"),r.ORDER)}function a(u,p=!0){return e.BASE.multiply(r.fromBytes(u)).toBytes(p)}function f(u){let{secretKey:p,publicKey:b,publicKeyUncompressed:w}=o,E=r._lengths;if(!pt(u))return;let A=O(u,void 0,"key").length,C=A===b||A===w,P=A===p||!!E?.includes(A);if(!(C&&P))return C}function d(u,p,b=!0){if(f(u)===!0)throw new Error("first arg must be private key");if(f(p)===!1)throw new Error("second arg must be public key");let w=r.fromBytes(u);return e.fromBytes(p).multiply(w).toBytes(b)}let h={isValidSecretKey:i,isValidPublicKey:s,randomSecretKey:c},l=Cr(c,a);return Object.freeze(h),Object.freeze(o),Object.freeze({getPublicKey:a,getSharedSecret:d,keygen:l,Point:e,utils:h,lengths:o})}function Xi(e,t,r={}){mt(e);let n=t;lt(n),me(r,{},{hmac:"function",lowS:"boolean",randomBytes:"function",bits2int:"function",bits2int_modN:"function"});let o=Object.assign({},r),i=o.randomBytes===void 0?Ir:o.randomBytes,s=o.hmac===void 0?(v,y)=>tt(n,v,y):o.hmac,{Fp:c,Fn:a}=e,{ORDER:f,BITS:d}=a,h=Rr(f),l=Vn(i,h),{keygen:u,getPublicKey:p,getSharedSecret:b,utils:w,lengths:E}=oa(e,o),A={prehash:!0,lowS:typeof o.lowS=="boolean"?o.lowS:!0,format:"compact",extraEntropy:!1},C=f*qi+nt<c.ORDER;function P(v){let y=f>>nt;return v>y}function J(v,y){if(!a.isValidNot0(y))throw new Error(`invalid signature ${v}: out of range 1..Point.Fn.ORDER`);return y}function N(){if(!c.isOdd)throw new Error("Field doesn't support isOdd")}function oe(v,y,x){return N(),(v===x?0:2)|Number(c.isOdd(y))}function be(){if(C)throw new Error('"recovered" sig type is not supported for cofactor >2 curves')}function ie(v,y){Qn(y);let x=E.signature,B=y==="compact"?x:y==="recovered"?x+1:void 0;return O(v,B)}class F{constructor(y,x,B){g(this,"r");g(this,"s");g(this,"recovery");if(this.r=J("r",y),this.s=J("s",x),B!=null){if(be(),![0,1,2,3].includes(B))throw new Error("invalid recovery id");this.recovery=B}Object.freeze(this)}static fromBytes(y,x=A.format){ie(y,x);let B;if(x==="der"){let{r:_,s:z}=Gn.toSig(O(y));return new F(_,z)}x==="recovered"&&(B=y[0],x="compact",y=y.subarray(1));let T=E.signature/2,$=y.subarray(0,T),I=y.subarray(T,T*2);return new F(a.fromBytes($),a.fromBytes(I),B)}static fromHex(y,x){return this.fromBytes($r(y),x)}assertRecovery(){let{recovery:y}=this;if(y==null)throw new Error("invalid recovery id: must be present");return y}addRecoveryBit(y){return new F(this.r,this.s,y)}recoverPublicKey(y){let{r:x,s:B}=this,T=this.assertRecovery(),$=T===2||T===3?x+f:x;if(!c.isValid($))throw new Error("invalid recovery id: sig.r+curve.n != R.x");let I=c.toBytes($),_=e.fromBytes(he(Yi((T&1)===0),I)),z=a.inv($),q=X(O(y,void 0,"msgHash")),ce=a.create(-q*z),D=a.create(B*z),j=e.BASE.mulAddUnsafe(ce,_,D);if(j.is0())throw new Error("invalid recovery: point at infinify");return j.assertValidity(),j}hasHighS(){return P(this.s)}toBytes(y=A.format){if(Qn(y),y==="der")return $r(Gn.hexFromSig(this));let{r:x,s:B}=this,T=a.toBytes(x),$=a.toBytes(B);return y==="recovered"?(be(),he(Uint8Array.of(this.assertRecovery()),T,$)):he(T,$)}toHex(y){return Ln(this.toBytes(y))}}Object.freeze(F.prototype),Object.freeze(F);let ve=o.bits2int===void 0?function(y){if(y.length>8192)throw new Error("input is too large");let x=te(y),B=y.length*8-d;return B>0?x>>BigInt(B):x}:o.bits2int,X=o.bits2int_modN===void 0?function(y){return a.create(ve(y))}:o.bits2int_modN,ke=jt(d);function se(v){return Fn("num < 2^"+d,v,Re,ke),a.toBytes(v)}function U(v,y){return O(v,void 0,"message"),y?O(n(v),void 0,"prehashed message"):v}function R(v,y,x){let{lowS:B,prehash:T,extraEntropy:$}=Xn(x,A);v=U(v,T);let I=X(v),_=a.fromBytes(y);if(!a.isValidNot0(_))throw new Error("invalid private key");let z=[se(_),se(I)];if($!=null&&$!==!1){let j=$===!0?i(E.secretKey):$;z.push(O(j,void 0,"extraEntropy"))}let q=he(...z),ce=I;function D(j){let dt=ve(j);if(!a.isValidNot0(dt))return;let It=e.BASE.multiply(dt).toAffine(),Fe=a.create(It.x);if(Fe===Re)return;let Be;if(l!==void 0){let Ot=te(Kt(l(h),f)),rc=a.inv(a.mul(Ot,dt)),nc=a.mul(Ot,ce),oc=a.mul(Ot,_);Be=a.create(rc*a.create(nc+oc*Fe))}else{let Ot=Ui(dt,f);Be=a.create(Ot*a.create(ce+Fe*_))}if(Be===Re)return;let fn=oe(It.x,It.y,Fe),No=Be;return B&&P(Be)&&(No=a.neg(Be),fn^=1),new F(Fe,No,C?void 0:fn)}return{seed:q,k2sig:D}}function m(v,y,x={}){let{seed:B,k2sig:T}=R(v,y,x);return Si(n.outputLen,a.BYTES,s)(B,T).toBytes(x.format)}function k(v,y,x,B={}){let{lowS:T,prehash:$,format:I}=Xn(B,A);if(x=O(x,void 0,"publicKey"),y=U(y,$),!pt(v)){let _=v instanceof F?", use sig.toBytes()":"";throw new Error("verify expects Uint8Array signature"+_)}ie(v,I);try{let _=F.fromBytes(v,I),z=e.fromBytes(x);if(T&&_.hasHighS())return!1;let{r:q,s:ce}=_,D=X(y),j=a.inv(ce),dt=a.create(D*j),It=a.create(q*j),Fe=e.BASE.mulAddUnsafe(dt,z,It);if(Fe.is0())return!1;let Be=Fe.toAffine();return!(a.create(Be.x)!==q||I==="recovered"&&_.recovery!==oe(Be.x,Be.y,q))}catch{return!1}}function S(v,y,x={}){let{prehash:B}=Xn(x,A);return y=U(y,B),F.fromBytes(v,"recovered").recoverPublicKey(y).toBytes()}return Object.freeze({keygen:u,getPublicKey:p,getSharedSecret:b,utils:w,lengths:E,Point:e,sign:m,verify:k,recoverPublicKey:S,Signature:F,hash:n})}var Nr={p:BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),n:BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),h:BigInt(1),a:BigInt(0),b:BigInt(7),Gx:BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),Gy:BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")},ia={beta:BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),basises:[[BigInt("0x3086d221a7d46bcde86c90e49284eb15"),-BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],[BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"),BigInt("0x3086d221a7d46bcde86c90e49284eb15")]]},sa=BigInt(0),Zi=BigInt(2);function ca(e){let t=Nr.p,r=BigInt(3),n=BigInt(6),o=BigInt(11),i=BigInt(22),s=BigInt(23),c=BigInt(44),a=BigInt(88),f=e*e*e%t,d=f*f*e%t,h=fe(d,r,t)*d%t,l=fe(h,r,t)*d%t,u=fe(l,Zi,t)*f%t,p=fe(u,o,t)*u%t,b=fe(p,i,t)*p%t,w=fe(b,c,t)*b%t,E=fe(w,a,t)*w%t,A=fe(E,c,t)*b%t,C=fe(A,r,t)*d%t,P=fe(C,s,t)*p%t,J=fe(P,n,t)*f%t,N=fe(J,Zi,t);if(!Et.eql(Et.sqr(N),e))throw new Error("Cannot find square root");return N}var Et=wt(Nr.p,{sqrt:ca}),ot=Vi(Nr,{Fp:Et,endo:ia}),xe=Xi(ot,Z),Qi=Object.create(null);function Hr(e,...t){let r=Qi[e];if(r===void 0){let n=Z(Bi(e));r=he(n,n),Qi[e]=r}return Z(he(r,...t))}var es=e=>e.toBytes(!0).slice(1),ts=({x:e})=>Et.toBytes(e),Fr=e=>!Et.isOdd(e);function rs(e){let{Fn:t,BASE:r}=ot,n=t.fromBytes(O(e,32,"secretKey")),i=r.multiply(n).toAffine();return{scalar:Fr(i.y)?n:t.neg(n),bytes:ts(i)}}function ns(e){let t=Et;if(!t.isValidNot0(e))throw new Error("invalid x: Fail if x \u2265 p");let r=t.sqr(e),n=t.add(t.mulN(r,e),BigInt(7)),o=t.sqrt(n);Fr(o)||(o=t.neg(o));let i=ot.fromAffine({x:e,y:o});return i.assertValidity(),i}var xt=te;function os(...e){return ot.Fn.create(xt(Hr("BIP0340/challenge",...e)))}function Ji(e){return rs(e).bytes}function aa(e,t,r=ht(32)){let{Fn:n,BASE:o}=ot,i=O(e,void 0,"message"),{bytes:s,scalar:c}=rs(t),a=O(r,32,"auxRand"),f=n.toBytes(c^xt(Hr("BIP0340/aux",a))),d=Hr("BIP0340/nonce",f,s,i),h=n.create(xt(d));if(h===sa)throw new Error("sign failed: k is zero");let u=o.multiply(h).toAffine(),p=Fr(u.y)?h:n.neg(h),b=ts(u),w=os(b,s,i),E=new Uint8Array(64);if(E.set(b,0),E.set(n.toBytes(n.create(p+w*c)),32),!is(E,i,s))throw new Error("sign: Invalid signature produced");return E}function is(e,t,r){let{Fp:n,Fn:o,BASE:i}=ot,s=O(e,64,"signature"),c=O(t,void 0,"message"),a=O(r,32,"publicKey");try{let f=ns(xt(a)),d=s.subarray(0,32),h=xt(d);if(!n.isValidNot0(h))return!1;let l=xt(s.subarray(32,64));if(!o.isValidNot0(l))return!1;let u=os(d,es(f),c),p=i.mulAddUnsafe(l,f,o.neg(u)),{x:b,y:w}=p.toAffine();return!(p.is0()||!Fr(w)||!n.eql(b,h))}catch{return!1}}var qt=(()=>{let r=n=>(n=n===void 0?ht(48):n,Kt(O(n,48,"seed"),Nr.n));return Object.freeze({keygen:Cr(r,Ji),getPublicKey:Ji,sign:aa,verify:is,Point:ot,utils:Object.freeze({randomSecretKey:r,taggedHash:Hr,lift_x:ns,pointToBytes:es}),lengths:Object.freeze({secretKey:32,publicKey:32,publicKeyHasPrefix:!1,signature:64,seed:48})})})();var fa=Uint8Array.from([7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8]),cs=Uint8Array.from(new Array(16).fill(0).map((e,t)=>t)),da=cs.map(e=>(9*e+5)%16),as=(()=>{let r=[[cs],[da]];for(let n=0;n<4;n++)for(let o of r)o.push(o[n].map(i=>fa[i]));return r})(),fs=as[0],ds=as[1],ls=[[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8],[12,13,11,15,6,9,9,7,12,15,11,13,7,8,7,7],[13,15,14,11,7,7,6,8,13,14,13,12,5,5,6,9],[14,11,12,14,8,6,5,5,15,12,15,14,9,9,8,6],[15,12,13,13,9,5,8,6,14,11,12,11,8,6,5,5]].map(e=>Uint8Array.from(e)),la=fs.map((e,t)=>e.map(r=>ls[t][r])),ua=ds.map((e,t)=>e.map(r=>ls[t][r])),ha=Uint32Array.from([0,1518500249,1859775393,2400959708,2840853838]),pa=Uint32Array.from([1352829926,1548603684,1836072691,2053994217,0]);function ss(e,t,r,n){return e===0?t^r^n:e===1?t&r|~t&n:e===2?(t|~r)^n:e===3?t&n|r&~n:t^(r|~n)}var Mr=new Uint32Array(16),Jn=class extends Je{constructor(){super(64,20,8,!0);g(this,"h0",1732584193);g(this,"h1",-271733879);g(this,"h2",-1732584194);g(this,"h3",271733878);g(this,"h4",-1009589776)}get(){let{h0:r,h1:n,h2:o,h3:i,h4:s}=this;return[r,n,o,i,s]}set(r,n,o,i,s){this.h0=r|0,this.h1=n|0,this.h2=o|0,this.h3=i|0,this.h4=s|0}_cloneInto(r){return(r||(r=new this.constructor)).set(...this.get()),this._cloneIntoMeta(r)}process(r,n){for(let p=0;p<16;p++,n+=4)Mr[p]=r.getUint32(n,!0);let o=this.h0|0,i=o,s=this.h1|0,c=s,a=this.h2|0,f=a,d=this.h3|0,h=d,l=this.h4|0,u=l;for(let p=0;p<5;p++){let b=4-p,w=ha[p],E=pa[p],A=fs[p],C=ds[p],P=la[p],J=ua[p];for(let N=0;N<16;N++){let oe=Ut(o+ss(p,s,a,d)+Mr[A[N]]+w,P[N])+l|0;o=l,l=d,d=Ut(a,10)|0,a=s,s=oe}for(let N=0;N<16;N++){let oe=Ut(i+ss(b,c,f,h)+Mr[C[N]]+E,J[N])+u|0;i=u,u=h,h=Ut(f,10)|0,f=c,c=oe}}this.set(this.h1+a+h|0,this.h2+d+u|0,this.h3+l+i|0,this.h4+o+c|0,this.h0+s+f|0)}roundClean(){ue(Mr)}destroy(){this.destroyed=!0,ue(this.buffer),this.set(0,0,0,0,0)}},zr=Lt(()=>new Jn);var Yt=xe.Point,Vt=Yt.Fn,eo=Ft(Z),ga=Uint8Array.from("Bitcoin seed".split(""),e=>e.charCodeAt(0)),to={private:76066276,public:76067358},ro=2147483648,ya=e=>zr(Z(e)),ba=e=>Te(e).getUint32(0,!1),vt=(e,t="number")=>{if(typeof e!="number")throw new TypeError(`"${t}" expected number, got type=${typeof e}`);if(!Number.isSafeInteger(e)||e<0||e>2**32-1)throw new RangeError(`"${t}" expected integer in range 0..2**32-1, got ${e}`);let r=new Uint8Array(4);return Te(r).setUint32(0,e,!1),r},no=(e,t="versions")=>{if(!(typeof e=="object"&&e!==null))throw new Error("versions must be an object");return vt(e.private,`${t}.private`),vt(e.public,`${t}.public`),e},Gt=class e{constructor(t){g(this,"versions");g(this,"depth",0);g(this,"index",0);g(this,"chainCode",null);g(this,"parentFingerprint",0);g(this,"_privateKey");g(this,"_publicKey");g(this,"pubHash");if(!t||typeof t!="object")throw new Error("HDKey.constructor must not be called directly");if(this.versions=t.versions?no(t.versions):to,this.depth=t.depth||0,this.chainCode=t.chainCode?Uint8Array.from(t.chainCode):null,this.index=t.index||0,this.parentFingerprint=t.parentFingerprint||0,!this.depth&&(this.parentFingerprint||this.index))throw new Error("HDKey: zero depth with non-zero index/parent fingerprint");if(this.depth>255)throw new Error("HDKey: depth exceeds the serializable value 255");if(t.publicKey&&t.privateKey)throw new Error("HDKey: publicKey and privateKey at same time.");if(t.privateKey){if(!xe.utils.isValidSecretKey(t.privateKey))throw new Error("Invalid private key");this._privateKey=Uint8Array.from(t.privateKey),this._publicKey=xe.getPublicKey(this._privateKey,!0)}else if(t.publicKey)this._publicKey=Yt.fromBytes(t.publicKey).toBytes(!0);else throw new Error("HDKey: no public or private key provided");this.pubHash=ya(this._publicKey)}get fingerprint(){if(!this.pubHash)throw new Error("No publicKey set!");return ba(this.pubHash)}get identifier(){return this.pubHash}get pubKeyHash(){return this.pubHash}get privateKey(){return this._privateKey||null}get publicKey(){return this._publicKey||null}get privateExtendedKey(){let t=this._privateKey;if(!t)throw new Error("No private key");return eo.encode(this.serialize(this.versions.private,Qe(Uint8Array.of(0),t)))}get publicExtendedKey(){if(!this._publicKey)throw new Error("No public key");return eo.encode(this.serialize(this.versions.public,this._publicKey))}static fromMasterSeed(t,r=to){if(K(t),r=no(r),8*t.length<128||8*t.length>512)throw new RangeError("HDKey: seed length must be between 128 and 512 bits; 256 bits is advised, got "+t.length);let n=tt(Ct,ga,t),o=n.slice(0,32),i=n.slice(32);return new e({versions:r,chainCode:i,privateKey:o})}static fromExtendedKey(t,r=to){r=no(r);let n=eo.decode(t),o=Te(n),i=o.getUint32(0,!1),s={versions:r,depth:n[4],parentFingerprint:o.getUint32(5,!1),index:o.getUint32(9,!1),chainCode:n.slice(13,45)},c=n.slice(45),a=c[0]===0;if(i!==r[a?"private":"public"])throw new Error("Version mismatch");return a?new e({...s,privateKey:c.slice(1)}):new e({...s,publicKey:c})}static fromJSON(t){return e.fromExtendedKey(t.xpriv)}derive(t){if(!/^[mM]'?/.test(t))throw new Error('Path must start with "m" or "M"');if(/^[mM]'?$/.test(t))return this;let r=t.replace(/^[mM]'?\//,"").split("/"),n=this;for(let o of r){let i=/^(\d+)('?)$/.exec(o),s=i&&i[1];if(!i||i.length!==3||typeof s!="string")throw new Error("invalid child index: "+o);let c=+s;if(!Number.isSafeInteger(c)||c>=ro)throw new Error("Invalid index");i[2]==="'"&&(c+=ro),n=n.deriveChild(c)}return n}deriveChild(t,r){if(!this._publicKey||!this.chainCode)throw new Error("No publicKey or chainCode set");let n=vt(t,"index");if(t>=ro){let a=this._privateKey;if(!a)throw new Error("Could not derive hardened child key");n=Qe(Uint8Array.of(0),a,n)}else n=Qe(this._publicKey,n);let o=r||tt(Ct,this.chainCode,n);K(o,64);let i=o.slice(0,32),s=o.slice(32),c={versions:this.versions,chainCode:s,depth:this.depth+1,parentFingerprint:this.fingerprint,index:t};if(c.depth>255)throw new Error("HDKey: depth exceeds the serializable value 255");try{let a=Vt.fromBytes(i);if(this._privateKey){let f=Vt.create(Vt.fromBytes(this._privateKey)+a);if(!Vt.isValidNot0(f))throw new Error("The tweak was out of range or the resulted private key is invalid");c.privateKey=Vt.toBytes(f)}else{let f=Yt.fromBytes(this._publicKey),d=a===0n?f:f.add(Yt.BASE.multiply(a));if(d.equals(Yt.ZERO))throw new Error("The tweak was equal to negative P, which made the result key invalid");c.publicKey=d.toBytes(!0)}return new e(c)}catch{return this.deriveChild(t+1)}}sign(t){if(!this._privateKey)throw new Error("No privateKey set!");return K(t,32),xe.sign(t,this._privateKey,{prehash:!1})}verify(t,r){if(K(t,32),K(r,64),!this._publicKey)throw new Error("No publicKey set!");return xe.verify(r,t,this._publicKey,{prehash:!1})}wipePrivateData(){return this._privateKey&&(this._privateKey.fill(0),this._privateKey=void 0),this}toJSON(){return{xpriv:this.privateExtendedKey,xpub:this.publicExtendedKey}}serialize(t,r){if(!this.chainCode)throw new Error("No chainCode set");return K(r,33),Qe(vt(t,"version"),new Uint8Array([this.depth]),vt(this.parentFingerprint,"parentFingerprint"),vt(this.index,"index"),this.chainCode,r)}};var Dr=Uint8Array.of();var wa=new Set(["__proto__","constructor","prototype"]),io=(e,t)=>{if(typeof e!="string")throw new Error(`${t} should be string, got ${typeof e}`);if(e.includes(".."))throw new TypeError(`${t} ${e} cannot contain path parent ..`);if(e.includes("/"))throw new TypeError(`${t} ${e} cannot contain path separator /`);if(wa.has(e))throw new Error(`${t} ${e} is reserved`)};function so(e,t){if(e.length!==t.length)return!1;for(let r=0;r<e.length;r++)if(e[r]!==t[r])return!1;return!0}function ps(e){if(e.length===1){let r=e[0];return(n,o=0)=>{let i=n.indexOf(r,o);return i===-1?void 0:i}}let t=new Uint32Array(e.length);for(let r=1,n=0;r<e.length;r++){for(;n&&e[r]!==e[n];)n=t[n-1];e[r]===e[n]&&(t[r]=++n)}return(r,n=0)=>{for(let o=n,i=0;o<r.length;o++){for(;i&&r[o]!==e[i];)i=t[i-1];if(r[o]===e[i]&&++i===e.length)return o-e.length+1}}}var ma=(e,t,r=0)=>ps(e)(t,r);function de(e){return e instanceof Uint8Array||ArrayBuffer.isView(e)&&e.constructor.name==="Uint8Array"&&"BYTES_PER_ELEMENT"in e&&e.BYTES_PER_ELEMENT===1}function xa(...e){let t=0;for(let n=0;n<e.length;n++){let o=e[n];if(!de(o))throw new Error("Uint8Array expected");t+=o.length}let r=new Uint8Array(t);for(let n=0,o=0;n<e.length;n++){let i=e[n];r.set(i,o),o+=i.length}return r}var fo=e=>new DataView(e.buffer,e.byteOffset,e.byteLength),Xt=BigInt(0),Ea=BigInt(1),us=BigInt(2);var hs=BigInt(10);function qe(e){return Object.prototype.toString.call(e)==="[object Object]"}function H(e){return Number.isSafeInteger(e)}var va=(e,t)=>Object.prototype.hasOwnProperty.call(e,t),kt=Object.freeze({equalBytes:so,isBytes:de,isCoder:Ue,checkBounds:ka,concatBytes:xa,createView:fo,isPlainObject:qe}),gs=e=>{if(e!==null&&typeof e!="string"&&!Ue(e)&&!de(e)&&!H(e))throw new TypeError(`lengthCoder: expected null | number | Uint8Array | CoderType, got ${e} (${typeof e})`);if(typeof e=="number"&&e<0)throw new Error(`lengthCoder: wrong length=${e}`);if(de(e)&&!e.length)throw new Error("lengthCoder: empty terminator");return{encodeStream(t,r){if(e===null)return;if(Ue(e))return e.encodeStream(t,r);let n;if(typeof e=="number"?n=e:typeof e=="string"&&(n=it.resolve(t.stack,e)),typeof n=="bigint"&&(n=Number(n)),!H(n)||n<0||n!==r)throw t.err(`Wrong length: ${n} len=${e} exp=${r} (${typeof r})`)},decodeStream(t){let r;if(Ue(e)?r=e.decodeStream(t):typeof e=="number"?r=e:typeof e=="string"&&(r=it.resolve(t.stack,e)),typeof r=="bigint")r=Number(r);else if(typeof r!="number")throw t.err(`Wrong length: ${r}`);if(!H(r)||r<0)throw t.err(`Wrong length: ${r}`);return r}}},Q=Object.freeze({BITS:32,FULL_MASK:-1>>>0,len:e=>{if(!H(e)||e<0)throw new Error(`wrong len=${e}`);return Math.ceil(e/32)},create:e=>new Uint32Array(Q.len(e)),clean:e=>e.fill(0),debug:e=>Array.from(e).map(t=>(t>>>0).toString(2).padStart(32,"0")),checkLen:(e,t)=>{if(Q.len(t)!==e.length)throw new Error(`wrong length=${e.length}. Expected: ${Q.len(t)}`)},chunkLen:(e,t,r)=>{if(!H(e)||e<0)throw new Error(`wrong bsLen=${e}`);if(!H(t)||t<0)throw new Error(`wrong pos=${t}`);if(!H(r)||r<0)throw new Error(`wrong len=${r}`);if(t>e-r)throw new Error(`wrong range=${t}/${r} of ${e}`)},set:(e,t,r,n=!0)=>!H(t)||t<0||t>=e.length||!n&&(e[t]&r)!==0?!1:(e[t]|=r,!0),pos:(e,t)=>({chunk:Math.floor((e+t)/32),mask:1<<32-(e+t)%32-1}),indices:(e,t,r=!1)=>{Q.checkLen(e,t);let{FULL_MASK:n,BITS:o}=Q,i=o-t%o,s=i?n>>>i<<i:n,c=[];for(let a=0;a<e.length;a++){let f=e[a];if(r&&(f=~f),a===e.length-1&&(f&=s),f!==0)for(let d=0;d<o;d++){let h=1<<o-d-1;f&h&&c.push(a*o+d)}}return c},range:e=>{let t=[],r;for(let n of e)r===void 0||n!==r.pos+r.length?t.push(r={pos:n,length:1}):r.length+=1;return t},rangeDebug:(e,t,r=!1)=>`[${Q.range(Q.indices(e,t,r)).map(n=>`(${n.pos}/${n.length})`).join(", ")}]`,setRange:(e,t,r,n,o=!0)=>{if(Q.chunkLen(t,r,n),n===0)return!0;let{FULL_MASK:i,BITS:s}=Q,c=r%s?Math.floor(r/s):void 0,a=r+n,f=a%s?Math.floor(a/s):void 0,d=(u,p)=>u>=0&&u<e.length&&(e[u]&p)===0;if(!o)if(c!==void 0&&c===f){if(!d(c,i>>>s-n<<s-n-r))return!1}else{if(c!==void 0&&!d(c,i>>>r%s))return!1;let u=c!==void 0?c+1:r/s,p=f!==void 0?f:a/s;for(let b=u;b<p;b++)if(!d(b,i))return!1;if(f!==void 0&&c!==f&&!d(f,i<<s-a%s))return!1}if(c!==void 0&&c===f)return Q.set(e,c,i>>>s-n<<s-n-r,o);if(c!==void 0&&!Q.set(e,c,i>>>r%s,o))return!1;let h=c!==void 0?c+1:r/s,l=f!==void 0?f:a/s;for(let u=h;u<l;u++)if(!Q.set(e,u,i,o))return!1;return!(f!==void 0&&c!==f&&!Q.set(e,f,i<<s-a%s,o))}}),it=Object.freeze({pushObj:(e,t,r)=>{e.push({obj:t}),r(),e.pop()},path:e=>{let t=[];for(let r of e)r.field!==void 0&&t.push(r.field===""?'""':`${r.field}`);return t.join("/")},err:(e,t,r)=>{let n=`${e}(${it.path(t)}): ${typeof r=="string"?r:r.message}`,o=r instanceof TypeError?new TypeError(n):r instanceof RangeError?new RangeError(n):new Error(n);if(r instanceof Error&&r.stack){let i=`${r.name}: ${r.message}`,s=`${o.name}: ${o.message}`;o.stack=r.stack.startsWith(i)?`${s}${r.stack.slice(i.length)}`:r.stack}return o},resolve:(e,t)=>{let r=t.split("/"),n=e.map(s=>s.obj),o=0;for(;o<r.length&&r[o]==="..";o++)n.pop();let i=n.pop();for(;o<r.length;o++){if(!i||i[r[o]]===void 0)return;i=i[r[o]]}return i}}),co=class e{constructor(t,r={},n=[],o=void 0,i=0){g(this,"pos",0);g(this,"data");g(this,"opts");g(this,"stack");g(this,"parent");g(this,"parentOffset");g(this,"bitBuf",0);g(this,"bitPos",0);g(this,"bs");g(this,"view");if(!de(t))throw new TypeError(`Reader: expected Uint8Array, got ${typeof t}`);if(!qe(r))throw new TypeError(`ReaderOpts: expected plain object, got ${r}`);if(r.allowUnreadBytes!==void 0&&typeof r.allowUnreadBytes!="boolean")throw new TypeError(`ReaderOpts.allowUnreadBytes: expected boolean, got ${typeof r.allowUnreadBytes}`);if(r.allowMultipleReads!==void 0&&typeof r.allowMultipleReads!="boolean")throw new TypeError(`ReaderOpts.allowMultipleReads: expected boolean, got ${typeof r.allowMultipleReads}`);this.data=t,this.opts=r,this.stack=n,this.parent=o,this.parentOffset=i,this.view=fo(t)}_enablePointers(){if(this.parent)return this.parent._enablePointers();this.bs||(this.bs=Q.create(this.data.length),Q.setRange(this.bs,this.data.length,0,this.pos,this.opts.allowMultipleReads))}markBytesBS(t,r){return this.parent?this.parent.markBytesBS(this.parentOffset+t,r):!r||!this.bs?!0:Q.setRange(this.bs,this.data.length,t,r,!1)}markBytes(t){let r=this.pos,n=this.markBytesBS(r,t);if(!this.opts.allowMultipleReads&&!n)throw this.err(`multiple read pos=${r} len=${t}`);return this.pos+=t,n}pushObj(t,r){return it.pushObj(this.stack,t,r)}enterField(t){let r=this.stack[this.stack.length-1];if(r===void 0||r.field!==void 0)throw this.err(`enterField: invalid stack state, field=${t}`);r.field=t}exitField(){this.stack[this.stack.length-1].field=void 0}readView(t,r){if(!H(t)||t<0)throw this.err(`readView: wrong length=${t}`);if(this.pos+t>this.data.length)throw this.err("readView: Unexpected end of buffer");let n=r(this.view,this.pos);return this.markBytes(t),n}absBytes(t){if(!H(t)||t<0||t>this.data.length)throw new Error("Unexpected end of buffer");return this.data.subarray(t)}finish(){if(!this.opts.allowUnreadBytes){if(this.bitPos)throw this.err(`${this.bitPos} bits left after unpack: ${M.encode(this.data.subarray(this.pos))}`);if(this.bs&&!this.parent){let t=Q.indices(this.bs,this.data.length,!0);if(t.length){let r=Q.range(t).map(({pos:n,length:o})=>`(${n}/${o})[${M.encode(this.data.subarray(n,n+o))}]`).join(", ");throw this.err(`unread byte ranges: ${r} (total=${this.data.length})`)}else return}if(!this.isEnd())throw this.err(`${this.leftBytes} bytes ${this.bitPos} bits left after unpack: ${M.encode(this.data.subarray(this.pos))}`)}}err(t){return it.err("Reader",this.stack,t)}offsetReader(t){if(!H(t)||t<0||t>this.data.length)throw this.err("offsetReader: Unexpected end of buffer");return new e(this.absBytes(t),this.opts,this.stack,this,t)}bytes(t,r=!1){if(this.bitPos)throw this.err("readBytes: bitPos not empty");if(!H(t)||t<0)throw this.err(`readBytes: wrong length=${t}`);if(this.pos+t>this.data.length)throw this.err("readBytes: Unexpected end of buffer");let n=this.data.subarray(this.pos,this.pos+t);return r||this.markBytes(t),n}byte(t=!1){if(this.bitPos)throw this.err("readByte: bitPos not empty");if(this.pos+1>this.data.length)throw this.err("readByte: Unexpected end of buffer");let r=this.data[this.pos];return t||this.markBytes(1),r}get leftBytes(){return this.data.length-this.pos}get totalBytes(){return this.data.length}isEnd(){return this.pos>=this.data.length&&!this.bitPos}progress(){return this.pos*8-this.bitPos}bits(t){if(!H(t)||t<0)throw this.err(`BitReader: wrong length=${t}`);if(t>32)throw this.err("BitReader: cannot read more than 32 bits in single call");let r=0;for(;t;){this.bitPos||(this.bitBuf=this.byte(),this.bitPos=8);let n=Math.min(t,this.bitPos);this.bitPos-=n,r=r<<n|this.bitBuf>>this.bitPos&2**n-1,this.bitBuf&=2**this.bitPos-1,t-=n}return r>>>0}find(t,r=this.pos){if(!de(t))throw this.err(`find: needle is not bytes! ${t}`);if(this.bitPos)throw this.err("find: bitPos not empty");if(!t.length)throw this.err("find: needle is empty");if(!H(r)||r<0)throw this.err(`find: wrong pos=${r}`);return ma(t,this.data,r)}},ao=class{constructor(t=[]){g(this,"pos",0);g(this,"stack");g(this,"buffers",[]);g(this,"chunks",[]);g(this,"chunk");g(this,"chunkView");g(this,"chunkPos",0);g(this,"run");g(this,"nextChunkSize",0);g(this,"ptrs",[]);g(this,"bitBuf",0);g(this,"bitPos",0);g(this,"finished",!1);this.stack=t}carve(t){if(this.chunk===void 0||this.chunk.length-this.chunkPos<t){let n=Math.max(t,this.nextChunkSize,64);this.nextChunkSize=Math.min(n*8,4096),this.chunk=new Uint8Array(n),this.chunkView=void 0,this.chunkPos=0,this.run=void 0,this.chunks.push(this.chunk)}let r=this.chunkPos;return this.run===void 0?(this.run={chunk:this.chunk,start:r,end:r+t},this.buffers.push(this.run)):this.run.end+=t,this.chunkPos=r+t,this.pos+=t,r}pushObj(t,r){return it.pushObj(this.stack,t,r)}enterField(t){let r=this.stack[this.stack.length-1];if(r===void 0||r.field!==void 0)throw this.err(`enterField: invalid stack state, field=${t}`);r.field=t}exitField(){this.stack[this.stack.length-1].field=void 0}writeView(t,r){if(this.finished)throw this.err("buffer: finished");if(!H(t)||t<0||t>8)throw new Error(`wrong writeView length=${t}`);if(this.bitPos)throw this.err("writeBytes: ends with non-empty bit buffer");let n=this.carve(t);this.chunkView===void 0&&(this.chunkView=fo(this.chunk)),r(this.chunkView,n)}err(t){return it.err("Writer",this.stack,t)}bytes(t){if(this.finished)throw this.err("buffer: finished");if(this.bitPos)throw this.err("writeBytes: ends with non-empty bit buffer");if(!de(t))throw this.err(`writeBytes: expected Uint8Array, got ${typeof t}`);this.buffers.push(t),this.run=void 0,this.pos+=t.length}byte(t){if(this.finished)throw this.err("buffer: finished");if(this.bitPos)throw this.err("writeByte: ends with non-empty bit buffer");if(!H(t)||t<0||t>255)throw this.err(`writeByte: wrong value=${t}`);let r=this.carve(1);this.chunk[r]=t}finish(t=!0){if(this.finished)throw this.err("buffer: finished");if(this.bitPos)throw this.err("buffer: ends with non-empty bit buffer");let r=this.buffers,n=0;for(let s=0;s<r.length;s++){let c=r[s];n+=de(c)?c.length:c.end-c.start}for(let s=0;s<this.ptrs.length;s++)n+=this.ptrs[s].buffer.length;let o=new Uint8Array(n),i=0;for(let s=0;s<r.length;s++){let c=r[s];de(c)?(o.set(c,i),i+=c.length):(o.set(c.chunk.subarray(c.start,c.end),i),i+=c.end-c.start)}for(let s=0;s<this.ptrs.length;s++)o.set(this.ptrs[s].buffer,i),i+=this.ptrs[s].buffer.length;for(let s=this.pos,c=0;c<this.ptrs.length;c++){let a=this.ptrs[c];o.set(a.ptr.encode(s),a.pos),s+=a.buffer.length}if(t){for(let s of this.chunks)s.fill(0);this.chunks=[],this.chunk=void 0,this.chunkView=void 0,this.chunkPos=0,this.run=void 0,this.buffers=[];for(let s of this.ptrs)s.buffer.fill(0);this.ptrs=[],this.finished=!0,this.bitBuf=0}return o}bits(t,r){if(this.finished)throw this.err("buffer: finished");if(!H(r)||r<0)throw this.err(`writeBits: wrong length=${r}`);if(r>32)throw this.err("writeBits: cannot write more than 32 bits in single call");if(!H(t)||t<0)throw this.err(`writeBits: wrong value=${t}`);if(t>=2**r)throw this.err(`writeBits: value (${t}) >= 2**bits (${r})`);for(;r;){let n=Math.min(r,8-this.bitPos);if(this.bitBuf=this.bitBuf<<n|t>>r-n,this.bitPos+=n,r-=n,t&=2**r-1,this.bitPos===8){this.bitPos=0;let o=this.carve(1);this.chunk[o]=this.bitBuf}}}},oo=e=>Uint8Array.from(e).reverse();function ka(e,t,r){if(r){if(t<=Xt)throw new Error(`checkBounds: signed bits must be positive, got ${t}`);let n=us**(t-Ea);if(e<-n||e>=n)throw new Error(`value out of signed bounds. Expected ${-n} <= ${e} < ${n}`)}else{let n=us**t;if(Xt>e||e>=n)throw new Error(`value out of unsigned bounds. Expected 0 <= ${e} < ${n}`)}}function ys(e){let t=e;return{encodeStream:t.encodeStream,decodeStream:t.decodeStream,size:t.size,encode:r=>{let n=new ao;return t.encodeStream(n,r),n.finish()},decode:(r,n={})=>{if(!de(r))throw new TypeError(`decode: expected Uint8Array, got ${typeof r}`);let o=new co(r,n),i=t.decodeStream(o);return o.finish(),i}}}function Bt(e,t){if(!Ue(e))throw new TypeError(`validate: invalid inner value ${e}`);if(typeof t!="function")throw new TypeError("validate: fn should be function");return ys({size:e.size,encodeStream:(r,n)=>{let o;try{o=t(n)}catch(i){throw r.err(i)}e.encodeStream(r,o)},decodeStream:r=>{let n=e.decodeStream(r);try{return t(n)}catch(o){throw r.err(o)}}})}var $e=e=>{let t=e;if(!qe(t))throw new TypeError(`wrap: invalid inner value ${t}`);if(typeof t.encodeStream!="function")throw new TypeError("wrap: encodeStream should be function");if(typeof t.decodeStream!="function")throw new TypeError("wrap: decodeStream should be function");if(t.size!==void 0&&(!H(t.size)||t.size<0))throw new TypeError(`wrap: invalid size ${t.size}`);if(t.validate!==void 0&&typeof t.validate!="function")throw new TypeError("wrap: validate should be function");let r=ys(t);return t.validate!==void 0?Bt(r,t.validate):r},jr=e=>qe(e)&&typeof e.decode=="function"&&typeof e.encode=="function";function Ue(e){return qe(e)&&jr(e)&&typeof e.encodeStream=="function"&&typeof e.decodeStream=="function"&&(e.size===void 0||H(e.size)&&e.size>=0)}function Ba(){return{encode:e=>{if(!Array.isArray(e))throw new Error("array expected");let t={},r=new Set;for(let n of e){if(!Array.isArray(n)||n.length!==2)throw new Error("array of two elements expected");let o=n[0],i=n[1];if(io(o,"dict: key"),r.has(o))throw new Error(`key(${o}) appears twice in struct`);r.add(o),t[o]=i}return t},decode:e=>{if(!qe(e))throw new Error(`expected plain object, got ${e}`);for(let t in e)io(t,"dict: key");return Object.entries(e)}}}var Sa=Object.freeze({encode:e=>{if(typeof e!="bigint")throw new Error(`expected bigint, got ${typeof e}`);if(e>BigInt(Number.MAX_SAFE_INTEGER))throw new Error(`element bigger than MAX_SAFE_INTEGER=${e}`);if(e<BigInt(Number.MIN_SAFE_INTEGER))throw new Error(`element smaller than MIN_SAFE_INTEGER=${e}`);return Number(e)},decode:e=>{if(!H(e))throw new Error("element is not a safe integer");return BigInt(e)}});function Ta(e){if(!qe(e))throw new Error("plain object expected");return{encode:t=>{if(!H(t)||!(t in e))throw new Error(`wrong value ${t}`);return e[t]},decode:t=>{if(typeof t!="string")throw new Error(`wrong value ${typeof t}`);let r=e[t];if(!va(e,t)||!H(r))throw new Error(`wrong value ${t}`);return r}}}function Aa(e,t=!1){if(!H(e)||e<0)throw new Error(`decimal/precision: wrong value ${e}`);if(typeof t!="boolean")throw new Error(`decimal/round: expected boolean, got ${typeof t}`);let r=hs**BigInt(e);return{encode:n=>{if(typeof n!="bigint")throw new Error(`expected bigint, got ${typeof n}`);let o=(n<Xt?-n:n).toString(10),i=o.length-e;i<0&&(o=o.padStart(o.length-i,"0"),i=0);let s=o.length-1;for(;s>=i&&o[s]==="0";s--);let c=o.slice(0,i),a=o.slice(i,s+1);return c||(c="0"),n<Xt&&(c="-"+c),a?`${c}.${a}`:c},decode:n=>{if(typeof n!="string")throw new Error(`expected string, got ${typeof n}`);let o=!1;if(n.startsWith("-")&&(o=!0,n=n.slice(1)),!/^(0|[1-9]\d*)(\.\d+)?$/.test(n))throw new Error(`wrong string value=${n}`);let i=n.indexOf(".");i=i===-1?n.length:i;let s=n.slice(0,i),c=n.slice(i+1).replace(/0+$/,""),a=BigInt(s)*r;if(!t&&c.length>e)throw new Error(`fractional part cannot be represented with this precision (num=${n}, prec=${e})`);let f=Math.min(c.length,e),d=BigInt(c.slice(0,f))*hs**BigInt(e-f),h=a+d;if(o&&h===Xt)throw new Error("negative zero is not allowed");return o?-h:h}}}function Pa(e){if(!Array.isArray(e))throw new Error(`expected array, got ${typeof e}`);for(let t of e)if(!jr(t))throw new Error(`wrong base coder ${t}`);return{encode:t=>{for(let r of e){let n;try{n=r.encode(t)}catch{continue}if(n!==void 0)return n}throw new Error(`match/encode: cannot find match in ${t}`)},decode:t=>{for(let r of e){let n;try{n=r.decode(t)}catch{continue}if(n!==void 0)return n}throw new Error(`match/decode: cannot find match in ${t}`)}}}var $a=e=>{if(!jr(e))throw new Error("BaseCoder expected");return{encode:t=>e.decode(t),decode:t=>e.encode(t)}},Zt=Object.freeze({dict:Ba,numberBigint:Sa,tsEnum:Ta,decimal:Aa,match:Pa,reverse:$a});var Ia=(e,t)=>$e({size:e,encodeStream:(r,n)=>r.writeView(e,(o,i)=>t.write(o,i,n)),decodeStream:r=>r.readView(e,t.read),validate:r=>{if(typeof r!="number")throw new TypeError(`viewCoder: expected number, got ${typeof r}`);return t.validate&&t.validate(r),r}}),lo=(e,t,r)=>{let n=e*8,o=2**(n-1),i=a=>{if(!H(a))throw new TypeError(`sintView: value is not safe integer: ${a}`);if(a<-o||a>=o)throw new RangeError(`sintView: value out of bounds. Expected ${-o} <= ${a} < ${o}`)},s=2**n,c=a=>{if(!H(a))throw new TypeError(`uintView: value is not safe integer: ${a}`);if(0>a||a>=s)throw new RangeError(`uintView: value out of bounds. Expected 0 <= ${a} < ${s}`)};return Ia(e,{write:r.write,read:r.read,validate:t?i:c})},Qt=Object.freeze(lo(4,!1,{read:(e,t)=>e.getUint32(t,!0),write:(e,t,r)=>e.setUint32(t,r,!0)}));var uo=Object.freeze(lo(2,!1,{read:(e,t)=>e.getUint16(t,!0),write:(e,t,r)=>e.setUint16(t,r,!0)}));var Kr=Object.freeze(lo(1,!1,{read:(e,t)=>e.getUint8(t),write:(e,t,r)=>e.setUint8(t,r)}));var Jt=(e,t=!1)=>{if(typeof t!="boolean")throw new TypeError(`bytes/le: expected boolean, got ${typeof t}`);let r=gs(e),n=de(e),o=n?Uint8Array.from(e):void 0,i=o&&o.length?ps(o):void 0;return $e({size:typeof e=="number"?e:void 0,encodeStream:(s,c)=>{n||r.encodeStream(s,c.length),s.bytes(t?oo(c):c),o&&s.bytes(o)},decodeStream:s=>{let c;if(o){let a=s.find(o);if(a===void 0)throw s.err("bytes: cannot find terminator");c=s.bytes(a-s.pos),s.bytes(o.length)}else c=s.bytes(e===null?s.leftBytes:r.decodeStream(s));return t?oo(c):c},validate:s=>{if(!de(s))throw new TypeError(`bytes: invalid value ${s}`);if(i){let c=t?oo(s):s;if(i(c)!==void 0)throw new Error("bytes: value contains terminator")}return s}})};function er(e,t){if(!Ue(e))throw new TypeError(`apply: invalid inner value ${e}`);if(!jr(t))throw new TypeError(`apply: invalid base value ${t}`);return $e({size:e.size,encodeStream:(r,n)=>{let o;try{o=t.decode(n)}catch(i){throw r.err(""+i)}return e.encodeStream(r,o)},decodeStream:r=>{let n=e.decodeStream(r);try{return t.encode(n)}catch(o){throw r.err(""+o)}}})}function Oa(e){let t=0;for(let r of e){if(r.size===void 0)return;if(!H(r.size))throw new Error(`sizeof: wrong element size=${r.size}`);t+=r.size}return t}function ho(e){if(!qe(e))throw new TypeError(`struct: expected plain object, got ${e}`);let t=[];for(let r in e){if(io(r,"struct: field"),!Ue(e[r]))throw new TypeError(`struct: field ${r} is not CoderType`);t.push(e[r])}return $e({size:Oa(t),encodeStream:(r,n)=>{let o=r;o.pushObj(n,()=>{for(let i in e)o.enterField(i),e[i].encodeStream(r,n[i]),o.exitField()})},decodeStream:r=>{let n={},o=r;return o.pushObj(n,()=>{for(let i in e)o.enterField(i),n[i]=e[i].decodeStream(r),o.exitField()}),n},validate:r=>{if(typeof r!="object"||r===null)throw new Error(`struct: invalid value ${r}`);return r}})}function po(e,t){if(!Ue(t))throw new TypeError(`array: invalid inner value ${t}`);let r=de(e)?Uint8Array.from(e):void 0,n=gs(typeof e=="string"?`../${e}`:r||e);if(e===null&&t.size===0)throw new Error("array: null length cannot use zero-size inner");if((Ue(e)||typeof e=="string")&&t.size===0)throw new Error("array: dynamic length cannot use zero-size inner");return $e({size:typeof e=="number"&&t.size!==void 0?e*t.size:void 0,encodeStream:(o,i)=>{let s=o;s.pushObj(i,()=>{r||n.encodeStream(o,i.length);for(let c=0;c<i.length;c++){s.enterField(c);let a=i[c],f=s.pos;if(t.encodeStream(o,a),r&&r.length<=s.pos-f){let d=s.finish(!1).subarray(f,s.pos);if(so(d.subarray(0,r.length),r))throw s.err(`array: inner element encoding same as separator. elm=${a} data=${d}`)}s.exitField()}}),r&&o.bytes(r)},decodeStream:o=>{let i=[],s=o;return s.pushObj(i,()=>{if(e===null)for(let c=0;!o.isEnd();c++){s.enterField(c);let a=s.progress();if(i.push(t.decodeStream(o)),s.progress()===a)throw o.err("array: inner decoder did not consume input");if(s.exitField(),t.size&&o.leftBytes<t.size)break}else if(r)for(let c=0;;c++){if(so(o.bytes(r.length,!0),r)){o.bytes(r.length);break}s.enterField(c);let a=s.progress();if(i.push(t.decodeStream(o)),s.progress()===a)throw o.err("array: inner decoder did not consume input");s.exitField()}else{s.enterField("arrayLen");let c=n.decodeStream(o);if(s.exitField(),t.size&&c*t.size>o.leftBytes)throw o.err(`array: length=${c} elements of size=${t.size} exceed ${o.leftBytes} bytes left`);for(let a=0;a<c;a++)s.enterField(a),i.push(t.decodeStream(o)),s.exitField()}}),i},validate:o=>{if(!Array.isArray(o))throw new Error(`array: invalid value ${o}`);return o}})}function Wr(e,t,r=()=>{}){if(!Array.isArray(e))throw new TypeError(`"${t}" expected array, got type=${typeof e}`);for(let n=0;n<e.length;n++)r(e[n],`${t}[${n}]`);return e}function qr(e,t=""){if(typeof e!="string"){let r=t&&`"${t}" `;throw new TypeError(r+"expected string, got type="+typeof e)}return e}function St(e,t={},r={},n="object"){return me(e,t,r)}var Vr=xe.Point;var _a=Vr.Fn.ORDER,Ra=BigInt(0),Ua=BigInt(2),La=e=>e%Ua===Ra,G=kt.isBytes,yo=kt.concatBytes,Ve=kt.equalBytes,tr=Z,rr=e=>zr(tr(e));var Yr=(e,t)=>xe.getPublicKey(e,t);var bo=(e,...t)=>qt.utils.taggedHash(e,...t),ne=Object.freeze({ecdsa:0,schnorr:1});function bs(e,t){let r=e.length;if(t===ne.ecdsa){if(r===32)throw new RangeError("Expected non-Schnorr key");return Vr.fromBytes(e),e}else if(t===ne.schnorr){if(r!==32)throw new RangeError("Expected 32-byte Schnorr key");return qt.utils.lift_x(te(e)),e}else throw new TypeError("Unknown key type")}function Ca(e,t){let n=qt.utils.taggedHash("TapTweak",e,t),o=te(n);if(o>=_a)throw new Error("tweak higher than curve order");return o}function wo(e,t){let r=qt.utils;O(e,32,"pubKey");let n=Ca(e,t),i=r.lift_x(te(e)).add(Vr.BASE.multiply(n)),s=La(i.y)?0:1;return[r.pointToBytes(i),s]}var Gr=tr(Vr.BASE.toBytes(!1)),Ie=Object.freeze({bech32:"bc",pubKeyHash:0,scriptHash:5,wif:128}),mo=Object.freeze({bech32:"tb",pubKeyHash:111,scriptHash:196,wif:239});function ws(e,t){if(!G(e)||!G(t))throw new TypeError(`cmp: wrong type a=${typeof e} b=${typeof t}`);let r=Math.min(e.length,t.length);for(let n=0;n<r;n++)if(e[n]!=t[n])return Math.sign(e[n]-t[n]);return Math.sign(e.length-t.length)}function ms(e){let t=Object.create(null);for(let r in e){if(t[e[r]]!==void 0)throw new Error("duplicate key");t[e[r]]=r}return t}var xo=520,nr=BigInt(0),xs=BigInt(1),Na=BigInt(2),Xr=BigInt(8),Es=BigInt(255),Fa=BigInt(252),ee=Object.freeze({OP_0:0,PUSHDATA1:76,PUSHDATA2:77,PUSHDATA4:78,"1NEGATE":79,RESERVED:80,OP_1:81,OP_2:82,OP_3:83,OP_4:84,OP_5:85,OP_6:86,OP_7:87,OP_8:88,OP_9:89,OP_10:90,OP_11:91,OP_12:92,OP_13:93,OP_14:94,OP_15:95,OP_16:96,NOP:97,VER:98,IF:99,NOTIF:100,VERIF:101,VERNOTIF:102,ELSE:103,ENDIF:104,VERIFY:105,RETURN:106,TOALTSTACK:107,FROMALTSTACK:108,"2DROP":109,"2DUP":110,"3DUP":111,"2OVER":112,"2ROT":113,"2SWAP":114,IFDUP:115,DEPTH:116,DROP:117,DUP:118,NIP:119,OVER:120,PICK:121,ROLL:122,ROT:123,SWAP:124,TUCK:125,CAT:126,SUBSTR:127,LEFT:128,RIGHT:129,SIZE:130,INVERT:131,AND:132,OR:133,XOR:134,EQUAL:135,EQUALVERIFY:136,RESERVED1:137,RESERVED2:138,"1ADD":139,"1SUB":140,"2MUL":141,"2DIV":142,NEGATE:143,ABS:144,NOT:145,"0NOTEQUAL":146,ADD:147,SUB:148,MUL:149,DIV:150,MOD:151,LSHIFT:152,RSHIFT:153,BOOLAND:154,BOOLOR:155,NUMEQUAL:156,NUMEQUALVERIFY:157,NUMNOTEQUAL:158,LESSTHAN:159,GREATERTHAN:160,LESSTHANOREQUAL:161,GREATERTHANOREQUAL:162,MIN:163,MAX:164,WITHIN:165,RIPEMD160:166,SHA1:167,SHA256:168,HASH160:169,HASH256:170,CODESEPARATOR:171,CHECKSIG:172,CHECKSIGVERIFY:173,CHECKMULTISIG:174,CHECKMULTISIGVERIFY:175,NOP1:176,CHECKLOCKTIMEVERIFY:177,CHECKSEQUENCEVERIFY:178,NOP4:179,NOP5:180,NOP6:181,NOP7:182,NOP8:183,NOP9:184,NOP10:185,CHECKSIGADD:186,INVALID:255}),Ma=Object.freeze(ms(ee));function vs(e=6,t=!1){return $e({encodeStream:(r,n)=>{if(n===nr)return;let o=n<0,i=BigInt(n),s=[];for(let c=o?-i:i;c;c>>=Xr)s.push(Number(c&Es));s[s.length-1]>=128?s.push(o?128:0):o&&(s[s.length-1]|=128),r.bytes(new Uint8Array(s))},decodeStream:r=>{let n=r.leftBytes;if(n>e)throw new Error(`ScriptNum: number (${n}) bigger than limit=${e}`);if(n===0)return nr;let o=r.bytes(n);if(t&&(o[n-1]&127)===0&&(n<=1||(o[n-2]&128)===0))throw new Error("Non-minimally encoded ScriptNum");let i=nr;for(let s=0;s<n;++s)i|=BigInt(o[s])<<Xr*BigInt(s);return o[n-1]>=128&&(i&=Na**BigInt(n*8)-xs>>xs,i=-i),i}})}function ks(e,t=4,r=!0){if(typeof e=="number")return e;if(G(e))try{let n=vs(t,r).decode(e);return n>Number.MAX_SAFE_INTEGER||n<-Number.MAX_SAFE_INTEGER?void 0:Number(n)}catch{return}}var za=(e,t)=>{if(ee.OP_0<e&&e<=ee.PUSHDATA4){if(e<ee.PUSHDATA1)return e;if(e===ee.PUSHDATA1)return t(1);if(e===ee.PUSHDATA2)return t(2);if(e===ee.PUSHDATA4)return t(4);throw new Error("Should be not possible")}},st=Object.freeze($e({encodeStream:(e,t)=>{Wr(t,"value");for(let r of t){if(typeof r=="string"){let o=ee[r];if(typeof o!="number")throw new Error(`Unknown opcode=${r}`);e.byte(o);continue}else if(typeof r=="number"){if(r===0){e.byte(0);continue}else if(r===-1){e.byte(ee["1NEGATE"]);continue}else if(1<=r&&r<=16){e.byte(ee.OP_1-1+r);continue}}typeof r=="number"&&(r=vs().encode(BigInt(r))),O(r,void 0,"value");let n=r.length;n<ee.PUSHDATA1?e.byte(n):n<=255?(e.byte(ee.PUSHDATA1),e.byte(n)):n<=65535?(e.byte(ee.PUSHDATA2),e.bytes(uo.encode(n))):(e.byte(ee.PUSHDATA4),e.bytes(Qt.encode(n))),e.bytes(r)}},decodeStream:e=>{let t=[];for(;!e.isEnd();){let r=e.byte(),n=za(r,o=>o===1?Kr.decodeStream(e):o===2?uo.decodeStream(e):Qt.decodeStream(e));if(n!==void 0)t.push(e.bytes(n));else if(r===0)t.push(0);else if(ee.OP_1<=r&&r<=ee.OP_16)t.push(r-(ee.OP_1-1));else{let o=Ma[r];if(o===void 0)throw new Error(`Unknown opcode=${r.toString(16)}`);t.push(o)}}return t}})),Da=(()=>{let e={253:[253,2,BigInt(253),BigInt(65535)],254:[254,4,BigInt(65536),BigInt(4294967295)],255:[255,8,BigInt(4294967296),BigInt("0xffffffffffffffff")]},t=Object.values(e);return Object.freeze($e({encodeStream:(r,n)=>{if(typeof n=="number"&&(n=BigInt(n)),nr<=n&&n<=Fa)return r.byte(Number(n));for(let[o,i,s,c]of t)if(!(s>n||n>c)){r.byte(o);for(let a=0;a<i;a++)r.byte(Number(n>>Xr*BigInt(a)&Es));return}throw r.err(`VarInt too big: ${n}`)},decodeStream:r=>{let n=r.byte();if(n<=252)return BigInt(n);let[o,i,s]=e[n],c=nr;for(let a=0;a<i;a++)c|=BigInt(r.byte())<<Xr*BigInt(a);if(c<s)throw r.err(`Wrong CompactSize(${8*i})`);return c}}))})();var ja=Object.freeze(Jt(Da)),Bs=ja;var Ka=ho({version:Kr,internalKey:Jt(32),merklePath:po(null,Jt(32))}),Ss=Object.freeze(Bt(Ka,e=>{if(e.merklePath.length>128)throw new Error("TaprootControlBlock: merklePath should be of length 0..128 (inclusive)");return e}));var Qr=Uint8Array.from([78,115]),Wa={encode(e){if(!(e.length!==2||e[0]!==1||!G(e[1])||!Ve(e[1],Qr)))return{type:"p2a",script:st.encode(e)}},decode:e=>{if(e.type==="p2a")return[1,Uint8Array.from(Qr)]}};function pe(e,t){try{return bs(e,t),!0}catch{return!1}}var qa={encode(e){if(!(e.length!==2||!G(e[0])||!pe(e[0],ne.ecdsa)||e[1]!=="CHECKSIG"))return{type:"pk",pubkey:e[0]}},decode:e=>{if(e.type==="pk")return[e.pubkey,"CHECKSIG"]}},Va={encode(e){if(!(e.length!==5||e[0]!=="DUP"||e[1]!=="HASH160"||!G(e[2]))&&e[2].length===20&&!(e[3]!=="EQUALVERIFY"||e[4]!=="CHECKSIG"))return{type:"pkh",hash:e[2]}},decode:e=>e.type==="pkh"?["DUP","HASH160",e.hash,"EQUALVERIFY","CHECKSIG"]:void 0},Ya={encode(e){if(!(e.length!==3||e[0]!=="HASH160"||!G(e[1])||e[2]!=="EQUAL")&&e[1].length===20)return{type:"sh",hash:e[1]}},decode:e=>e.type==="sh"?["HASH160",e.hash,"EQUAL"]:void 0},Ga={encode(e){if(!(e.length!==2||e[0]!==0||!G(e[1]))&&e[1].length===32)return{type:"wsh",hash:e[1]}},decode:e=>e.type==="wsh"?[0,e.hash]:void 0},Xa={encode(e){if(!(e.length!==2||e[0]!==0||!G(e[1]))&&e[1].length===20)return{type:"wpkh",hash:e[1]}},decode:e=>e.type==="wpkh"?[0,e.hash]:void 0},Za={encode(e){let t=e.length-1;if(e[t]!=="CHECKMULTISIG")return;let r=e[0],n=e[t-1];if(typeof r!="number"||typeof n!="number")return;let o=e.slice(1,-2);if(n===o.length){for(let i of o)if(!G(i)||!pe(i,ne.ecdsa))return;if(!(!Number.isSafeInteger(r)||r<1||r>n))return{type:"ms",m:r,pubkeys:o}}},decode:e=>e.type==="ms"?[e.m,...e.pubkeys,e.pubkeys.length,"CHECKMULTISIG"]:void 0},Qa={encode(e){if(!(e.length!==2||e[0]!==1||!G(e[1])||e[1].length!==32)&&pe(e[1],ne.schnorr))return{type:"tr",pubkey:e[1]}},decode:e=>e.type==="tr"?[1,e.pubkey]:void 0},Ja={encode(e){let t=e.length-1;if(e[t]!=="CHECKSIG")return;let r=[];for(let n=0;n<t;n++){let o=e[n];if(n&1){if(o!=="CHECKSIGVERIFY"||n===t-1)return;continue}if(!G(o)||!pe(o,ne.schnorr))return;r.push(o)}if(r.length)return{type:"tr_ns",pubkeys:r}},decode:e=>{if(e.type!=="tr_ns")return;let t=[];for(let r=0;r<e.pubkeys.length-1;r++)t.push(e.pubkeys[r],"CHECKSIGVERIFY");return t.push(e.pubkeys[e.pubkeys.length-1],"CHECKSIG"),t}},ef={encode(e){let t=e.length-1;if(e[t]!=="NUMEQUAL"||e[1]!=="CHECKSIG")return;let r=[],n=ks(e[t-1]);if(typeof n=="number"){for(let o=0;o<t-1;o++){let i=e[o];if(o&1){if(i!==(o===1?"CHECKSIG":"CHECKSIGADD"))return;continue}if(!G(i)||!pe(i,ne.schnorr))return;r.push(i)}if(!(!Number.isSafeInteger(n)||n<1||n>r.length||r.length>999))return{type:"tr_ms",pubkeys:r,m:n}}},decode:e=>{if(e.type!=="tr_ms")return;let t=[e.pubkeys[0],"CHECKSIG"];for(let r=1;r<e.pubkeys.length;r++)t.push(e.pubkeys[r],"CHECKSIGADD");return t.push(e.m,"NUMEQUAL"),t}},tf={encode(e){return{type:"unknown",script:st.encode(e)}},decode:e=>e.type==="unknown"?st.decode(e.script):void 0},rf=[Wa,qa,Va,Ya,Ga,Xa,Za,Qa,Ja,ef,tf],nf=er(st,Zt.match(rf)),Oe=Object.freeze(Bt(nf,e=>{if(e.type==="pk"&&!pe(e.pubkey,ne.ecdsa))throw new Error("OutScript/pk: wrong key");if((e.type==="pkh"||e.type==="sh"||e.type==="wpkh")&&(!G(e.hash)||e.hash.length!==20))throw new Error(`OutScript/${e.type}: wrong hash`);if(e.type==="wsh"&&(!G(e.hash)||e.hash.length!==32))throw new Error("OutScript/wsh: wrong hash");if(e.type==="tr"&&(!G(e.pubkey)||!pe(e.pubkey,ne.schnorr)))throw new Error("OutScript/tr: wrong taproot public key");if((e.type==="ms"||e.type==="tr_ns"||e.type==="tr_ms")&&!Array.isArray(e.pubkeys))throw new Error("OutScript/multisig: wrong pubkeys array");if(e.type==="ms"){let t=e.pubkeys.length;for(let r of e.pubkeys)if(!pe(r,ne.ecdsa))throw new Error("OutScript/multisig: wrong pubkey");if(V(e.m,"m"),e.m<=0||t>16||e.m>t)throw new Error("OutScript/multisig: invalid params")}if(e.type==="tr_ns"||e.type==="tr_ms"){for(let t of e.pubkeys)if(!pe(t,ne.schnorr))throw new Error(`OutScript/${e.type}: wrong pubkey`)}if(e.type==="tr_ms"){let t=e.pubkeys.length;if(V(e.m,"m"),e.m<=0||t>999||e.m>t)throw new Error("OutScript/tr_ms: invalid params")}return e}));function Ts(e,t){if(!Ve(e.hash,tr(t)))throw new Error("checkScript: wsh wrong witnessScript hash");let r=Oe.decode(t);if(r.type==="tr"||r.type==="tr_ns"||r.type==="tr_ms")throw new Error(`checkScript: P2${r.type} cannot be wrapped in P2SH`);if(r.type==="wpkh"||r.type==="wsh"||r.type==="sh")throw new Error(`checkScript: P2${r.type} cannot be wrapped in P2WSH`)}function of(e,t,r){let n=!1,o;if(e){let i=Oe.decode(e);if(i.type==="tr_ns"||i.type==="tr_ms"||i.type==="ms"||i.type=="pk")throw new Error(`checkScript: non-wrapped ${i.type}`);if(t){if(i.type!=="sh")throw new Error("checkScript: redeemScript without P2SH");if(!Ve(i.hash,rr(t)))throw new Error("checkScript: sh wrong redeemScript hash");if(o=Oe.decode(t),o?.type==="tr"||o?.type==="tr_ns"||o?.type==="tr_ms")throw new Error(`checkScript: P2${o.type} cannot be wrapped in P2SH`);if(o?.type==="sh")throw new Error("checkScript: P2SH cannot be wrapped in P2SH")}i.type==="wsh"&&(n=!0,r&&Ts(i,r))}if(t&&(o===void 0&&(o=Oe.decode(t)),o?.type==="wsh"&&(n=!0,r&&Ts(o,r))),r&&!n)throw new Error("checkScript: witnessScript without P2WSH")}var ir=(e,t=Ie)=>{if(!pe(e,ne.ecdsa))throw new Error("P2PKH: invalid publicKey");let r=rr(e);return{type:"pkh",script:Oe.encode({type:"pkh",hash:r}),address:or(t).encode({type:"pkh",hash:r}),hash:r}},Jr=(e,t=Ie)=>{St(e,{},{},"child");let r=e,n=r.script;if(!G(n))throw new Error(`Wrong script: ${typeof r.script}, expected Uint8Array`);if(n.length>xo)throw new Error(`P2SH: redeemScript exceeds ${xo}-byte push limit: len=${n.length}`);let o=rr(n),i={type:"sh",hash:o},s=Oe.encode(i),c=or(t).encode(i);return of(s,n,r.witnessScript),r.witnessScript?{type:"sh",redeemScript:n,script:s,address:c,hash:o,witnessScript:r.witnessScript}:{type:"sh",redeemScript:n,script:s,address:c,hash:o}};var Tt=(e,t=Ie)=>{if(!pe(e,ne.ecdsa))throw new Error("P2WPKH: invalid publicKey");if(e.length===65)throw new Error("P2WPKH: uncompressed public key");let r=rr(e);return{type:"wpkh",script:Oe.encode({type:"wpkh",hash:r}),address:or(t).encode({type:"wpkh",hash:r}),hash:r}};function sf(e,t,r=!1,n){let o=Oe.decode(e);if(o.type==="unknown"){if(n){let s=er(st,Zt.match(n)),c;try{c=s.decode(e)}catch{c=void 0}if(c!==void 0){if(!qr(c.type,"c.type").startsWith("tr_"))throw new Error(`P2TR: invalid custom type=${c.type}`);return}}if(r)return}if(!["tr_ns","tr_ms"].includes(o.type))throw new Error(`P2TR: invalid leaf script=${o.type}`);let i=o;if(!r&&i.pubkeys)for(let s of i.pubkeys){if(Ve(s,Gr))throw new Error("Unspendable taproot key in leaf script");if(Ve(s,t))throw new Error("Using P2TR with leaf script with same key as internal key is not supported")}}function cf(e){if(Wr(e,"taprootList",(n,o)=>{Array.isArray(n)||(St(n,{},{},o),n.weight!==void 0&&V(n.weight,o+".weight"))}),!e.length)throw new Error("taprootListToTree: empty tree");let t=Array.from(e);for(;t.length>=2;){t.sort((s,c)=>(c.weight||1)-(s.weight||1));let n=t.pop(),o=t.pop(),i=(o?.weight||1)+(n?.weight||1);t.push({weight:i,childs:[o?.childs||o,n?.childs||n]})}let r=t[0];return r?.childs||r}function Eo(e,t=[]){if(!e)throw new Error("taprootAddPath: empty tree");if(e.type==="leaf")return{...e,path:t};if(e.type!=="branch")throw new Error(`taprootAddPath: wrong type=${e}`);return{...e,path:t,left:Eo(e.left,[e.right.hash,...t]),right:Eo(e.right,[e.left.hash,...t])}}function vo(e){if(!e)throw new Error("taprootAddPath: empty tree");if(e.type==="leaf")return[e];if(e.type!=="branch")throw new Error(`taprootWalkTree: wrong type=${e}`);return[...vo(e.left),...vo(e.right)]}function ko(e,t,r=!1,n){if(e===void 0)throw new Error("taprootHashTree: empty tree");if(!Array.isArray(e)&&!kt.isPlainObject(e))throw new TypeError('"tree" expected object or array, got type='+typeof e);if(Array.isArray(e)&&e.length===1&&(e=e[0]),!Array.isArray(e)){St(e,{},{},"tree");let a=e.leafVersion,{script:f}=e;if(e.tapLeafScript||e.tapMerkleRoot&&!Ve(e.tapMerkleRoot,Dr))throw new Error("P2TR: tapRoot leafScript cannot have tree");let d=typeof f=="string"?M.decode(f):O(f,void 0,"tree.script");return sf(d,t,r,n),{type:"leaf",version:a,script:d,hash:af(d,Bo(a))}}if(e.length!==2&&(e=cf(e)),e.length!==2)throw new Error("hashTree: non binary tree!");let o=ko(e[0],t,r,n),i=ko(e[1],t,r,n),[s,c]=[o.hash,i.hash];return ws(c,s)===-1&&([s,c]=[c,s]),{type:"branch",left:o,right:i,hash:bo("TapBranch",s,c)}}var Ps=192,Bo=e=>{if(e===void 0)return Ps;if(V(e,"leafVersion"),e>254||e===80||e&1)throw new Error(`P2TR: invalid leafVersion=${e}`);return e},af=(e,t=Ps)=>bo("TapLeaf",new Uint8Array([Bo(t)]),Bs.encode(e));function en(e,t,r=Ie,n=!1,o){if(!e&&!t)throw new Error("p2tr: should have pubKey or scriptTree (or both)");let i=typeof e=="string"?M.decode(e):e||Gr;if(!pe(i,ne.schnorr))throw new Error("p2tr: non-schnorr pubkey");if(t){let s=Eo(ko(t,i,n,o)),c=s.hash,[a,f]=wo(i,c),d=[],h=vo(s).map(l=>{let u=Bo(l.version),p={version:u+f,internalKey:i,merklePath:l.path};return d.push([p,yo(l.script,new Uint8Array([u]))]),{...l,controlBlock:Ss.encode(p)}});return{type:"tr",script:Oe.encode({type:"tr",pubkey:a}),address:or(r).encode({type:"tr",pubkey:a}),tweakedPubkey:a,tapInternalKey:i,leaves:h,tapLeafScript:d,tapMerkleRoot:c}}else{let s=wo(i,Dr)[0];return{type:"tr",script:Oe.encode({type:"tr",pubkey:s}),address:or(r).encode({type:"tr",pubkey:s}),tweakedPubkey:s,tapInternalKey:i}}}var $s=Ft(tr);function Is(e,t){if(t.length<2||t.length>40)throw new Error("Witness: invalid length");if(e>16)throw new Error("Witness: invalid version");if(e===0&&!(t.length===20||t.length===32))throw new Error("Witness: invalid length for version")}function Zr(e,t,r=Ie){Is(e,t);let n=e===0?mr:An;return n.encode(r.bech32,[e].concat(n.toWords(t)))}function As(e,t){return $s.encode(yo(Uint8Array.from(t),e))}function or(e=Ie){return St(e,{},{},"network"),{encode(t){St(t,{},{},"from");let{type:r}=t;if(qr(r,"from.type"),r==="wpkh")return Zr(0,t.hash,e);if(r==="wsh")return Zr(0,t.hash,e);if(r==="tr")return Zr(1,t.pubkey,e);if(r==="p2a")return Zr(1,Qr,e);if(r==="pkh")return As(t.hash,[e.pubKeyHash]);if(r==="sh")return As(t.hash,[e.scriptHash]);throw new Error(`Unknown address type=${r}`)},decode(t){if(qr(t,"address"),t.length<14||t.length>74)throw new Error("Invalid address length");if(e.bech32&&t.toLowerCase().startsWith(`${e.bech32}1`)){let n;try{if(n=mr.decode(t),n.words[0]!==0)throw new Error(`bech32: wrong version=${n.words[0]}`)}catch{if(n=An.decode(t),n.words[0]===0)throw new Error(`bech32m: wrong version=${n.words[0]}`)}if(n.prefix!==e.bech32)throw new Error(`wrong bech32 prefix=${n.prefix}`);let[o,...i]=n.words,s=mr.fromWords(i);if(Is(o,s),o===0&&s.length===32)return{type:"wsh",hash:s};if(o===0&&s.length===20)return{type:"wpkh",hash:s};if(o===1&&s.length===32)return{type:"tr",pubkey:s};if(o===1&&Ve(s,Qr))return{type:"p2a",script:st.encode([1,s])};throw new Error("Unknown witness program")}let r=$s.decode(t);if(r.length!==21)throw new Error("Invalid base58 address");if(r[0]===e.pubKeyHash)return{type:"pkh",hash:r.slice(1)};if(r[0]===e.scriptHash)return{type:"sh",hash:r.slice(1)};throw new Error(`Invalid address prefix=${r[0]}`)}}}var sr=fi(Z),ff=BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),To=[{id:"bip44",bip:"BIP44",label:"Legacy",short:"Legacy 1\u2026",beginner:"Addresses that start with 1. Oldest type. Bitcoin Core can import these with importprivkey.",script:"p2pkh",purpose:44,slip:"x"},{id:"bip49",bip:"BIP49",label:"Nested SegWit",short:"Nested 3\u2026",beginner:"Addresses that start with 3. A SegWit script wrapped so older wallets can still send to it.",script:"p2sh-p2wpkh",purpose:49,slip:"y"},{id:"bip84",bip:"BIP84",label:"Native SegWit",short:"SegWit bc1q\u2026",beginner:"Addresses that start with bc1q. The default in Bitcoin Core, Sparrow, and Electrum today.",script:"p2wpkh",purpose:84,slip:"z"},{id:"bip86",bip:"BIP86",label:"Taproot",short:"Taproot bc1p\u2026",beginner:"Addresses that start with bc1p. Newest type. Use this if your wallet speaks Taproot.",script:"p2tr",purpose:86,slip:"v"}],cr={mainnet:{x:{pub:76067358,prv:76066276,pubName:"xpub",prvName:"xprv"},y:{pub:77429938,prv:77428856,pubName:"ypub",prvName:"yprv"},z:{pub:78792518,prv:78791436,pubName:"zpub",prvName:"zprv"},v:{pub:73342198,prv:73341116,pubName:"vpub",prvName:"vprv"}},testnet:{x:{pub:70617039,prv:70615956,pubName:"tpub",prvName:"tprv"},y:{pub:71979618,prv:71978536,pubName:"upub",prvName:"uprv"},z:{pub:73342198,prv:73341116,pubName:"vpub",prvName:"vprv"},v:{pub:39277699,prv:39276616,pubName:"npub",prvName:"nprv"}}};function _s(e){return e==="mainnet"?Ie:mo}function df(e){return e==="mainnet"?128:239}function Rs(e){return e==="mainnet"?0:1}function Ao(e,t,r=0){return`m/${e.purpose}'/${Rs(t)}'/${r}'`}function Us(e){return(e>>>0).toString(16).padStart(8,"0")}function le(e,t){let r=sr.decode(e),n=new Uint8Array(r);return n[0]=t>>>24&255,n[1]=t>>>16&255,n[2]=t>>>8&255,n[3]=t&255,sr.encode(n)}function lf(e){let t=sr.decode(e.trim());return(t[0]<<24|t[1]<<16|t[2]<<8|t[3])>>>0}var So=[];for(let e of Object.values(cr))for(let t of Object.values(e))So.push({ver:t.prv,private:!0}),So.push({ver:t.pub,private:!1});function uf(e){let t=lf(e),r=So.find(o=>o.ver===t);if(!r)throw new Error("Not a recognized extended key (xprv/xpub/ypub/zpub/vpub).");let n=r.private?cr.mainnet.x.prv:cr.mainnet.x.pub;return{xkey:le(e,n),isPrivate:r.private}}function rn(e,t,r){let n=new Uint8Array([df(r)]),o=t?Os(n,e,new Uint8Array([1])):Os(n,e);return sr.encode(o)}function Ls(e){let t=sr.decode(e.trim());if(t.length!==33&&t.length!==34)throw new Error("WIF decoded to an unexpected length.");let r=t[0],n;if(r===128)n="mainnet";else if(r===239)n="testnet";else throw new Error("WIF prefix is not Bitcoin mainnet (5/K/L) or testnet (9/c).");if(t.length===34){if(t[33]!==1)throw new Error("Compressed WIF is missing the 0x01 suffix.");return{priv:t.slice(1,33),compressed:!0,network:n}}return{priv:t.slice(1),compressed:!1,network:n}}function Os(...e){let t=e.reduce((o,i)=>o+i.length,0),r=new Uint8Array(t),n=0;for(let o of e)r.set(o,n),n+=o.length;return r}function hf(e){if(e.length!==32)throw new Error("Private key must be 32 bytes.");let t=BigInt("0x"+M.encode(e));if(t===0n||t>=ff)throw new Error("Private key is out of the secp256k1 range.");xe.getPublicKey(e,!0)}function pf(e,t,r){let n=_s(r);switch(e){case"p2pkh":{let o=ir(t,n).address;if(!o)throw new Error("Failed to build legacy address");return o}case"p2sh-p2wpkh":{let o=Jr(Tt(t,n),n).address;if(!o)throw new Error("Failed to build nested SegWit address");return o}case"p2wpkh":{let o=Tt(t,n).address;if(!o)throw new Error("Failed to build SegWit address");return o}case"p2tr":{let o=en(t.slice(1),void 0,n).address;if(!o)throw new Error("Failed to build Taproot address");return o}}}function nn(e,t,r,n,o,i){let s=i==="receive"?0:1,c=[];for(let a=0;a<o;a++){let f=e.derive(`m/${s}/${a}`),d=f.publicKey;if(!d)throw new Error("Missing public key");let h=f.privateKey;c.push({index:a,role:i,path:`${t}/${s}/${a}`,address:pf(r,d,n),wif:h?rn(h,!0,n):null,pubkey:M.encode(d),privHex:h?M.encode(h):null})}return c}var gf="0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ",yf="qpzry9x8gf2tvdw0s3jn54khce6mua7l";function bf(e){let t=[],r=[];for(let n of e){let o=gf.indexOf(n);if(o<0)throw new Error(`Invalid descriptor character: ${n}`);r.push(o&31),t.push(o>>5),t.length===3&&(r.push(t[0]*9+t[1]*3+t[2]),t.length=0)}return t.length===1?r.push(t[0]):t.length===2&&r.push(t[0]*3+t[1]),r}function wf(e){let t=[0xf5dee51989n,0xa9fdca3312n,0x1bab10e32dn,0x3706b1677an,0x644d626ffdn],r=1n;for(let n of e){let o=r>>35n;r=(r&0x7ffffffffn)<<5n^BigInt(n);for(let i=0;i<5;i++)(o>>BigInt(i)&1n)!==0n&&(r^=t[i])}return r}function Cs(e){let t=bf(e).concat([0,0,0,0,0,0,0,0]),r=wf(t)^1n,n="";for(let o=0;o<8;o++){let i=Number(r>>BigInt(5*(7-o))&31n);n+=yf[i]}return n}function Le(e){return`${e}#${Cs(e)}`}function Ye(e,t){switch(e){case"p2pkh":return`pkh(${t})`;case"p2sh-p2wpkh":return`sh(wpkh(${t}))`;case"p2wpkh":return`wpkh(${t})`;case"p2tr":return`tr(${t})`}}function tn(e,t,r,n,o,s=0){let i=Rs(r);return`[${e}/${t.purpose}h/${i}h/${s}h]${n}/${o}/*`}function mf(e,t,r,n,o,q=0){let i=Ao(t,r,q),s=e.derive(i),c=s.publicExtendedKey,a=s.privateExtendedKey??null,f=cr[r],d=le(c,f.y.pub),h=le(c,f.z.pub),l=le(c,f.v.pub),u=a?le(a,f.y.prv):null,p=a?le(a,f.z.prv):null,b=a?le(a,f.v.prv):null,w=tn(o,t,r,c,0,q),E=tn(o,t,r,c,1,q),A=a?tn(o,t,r,a,0,q):null,C=a?tn(o,t,r,a,1,q):null;return{def:t,accountPath:i,xprv:a,xpub:c,ypub:d,yprv:u,zpub:h,zprv:p,vpub:l,vprv:b,receiveDescriptor:Le(Ye(t.script,w)),changeDescriptor:Le(Ye(t.script,E)),receiveDescriptorPriv:A?Le(Ye(t.script,A)):null,changeDescriptorPriv:C?Le(Ye(t.script,C)):null,receive:nn(s,i,t.script,r,n,"receive"),change:nn(s,i,t.script,r,n,"change")}}function Hs(e,t,r,n,o=0){let i=Math.min(Math.max(r,1),50),s=Us(e.fingerprint),c=To.map(a=>mf(e,a,t,i,s,o));return{kind:"hd",network:t,mnemonic:n.mnemonic,passphraseUsed:n.passphraseUsed,entropyHex:n.entropyHex,seedHex:n.seedHex,rootXprv:e.privateExtendedKey??null,rootXpub:e.publicExtendedKey,masterFingerprint:s,notes:n.notes,warnings:n.warnings,accounts:c}}function on(e,t,r,n,o=0){let i=_n(e.bytes);return ar(i,t,r,n,{entropyHex:e.hex,notes:e.notes,warnings:e.warnings},o)}function ar(e,t,r,n,o,p=0){let i=Mt(e);if(!i.ok)throw new Error(i.error??"Invalid seed phrase");let s=i.words.join(" "),c=wi(s,t),a=Gt.fromMasterSeed(c),f=o?.entropyHex??null;f||(f=M.encode(Er(s,Ae)));let d=[...o?.warnings??[]];return t.length>0&&d.push("A passphrase is in use. The same words without this passphrase are a different wallet. Do not store the passphrase with the words."),Hs(a,r,n,{mnemonic:s,passphraseUsed:t.length>0,entropyHex:f,seedHex:M.encode(c),notes:o?.notes??[],warnings:d},p)}function Po(e,t,r,q=0){let n=e.trim(),{xkey:o,isPrivate:i}=uf(n),s=Gt.fromExtendedKey(o),c=[i?"Imported an extended private key. Addresses and WIF keys are derived from it.":"Imported an extended public key. This is watch-only: addresses can be generated, spending keys cannot."];if(s.depth===0)return Hs(s,t,r,{mnemonic:null,passphraseUsed:!1,entropyHex:null,seedHex:null,notes:c,warnings:i?[]:["Watch-only. Private keys are not in this key."]},q);let a=Us(s.parentFingerprint||s.fingerprint),f=Math.min(Math.max(r,1),50),d=To.map(h=>{let l=s.publicExtendedKey,u=i?s.privateExtendedKey:null,p=cr[t],b=`imported/${h.id}`,w=`[${a}]${l}/0/*`,E=`[${a}]${l}/1/*`,A=u?`[${a}]${u}/0/*`:null,C=u?`[${a}]${u}/1/*`:null;return{def:h,accountPath:b,xprv:u,xpub:l,ypub:le(l,p.y.pub),yprv:u?le(u,p.y.prv):null,zpub:le(l,p.z.pub),zprv:u?le(u,p.z.prv):null,vpub:le(l,p.v.pub),vprv:u?le(u,p.v.prv):null,receiveDescriptor:Le(Ye(h.script,w)),changeDescriptor:Le(Ye(h.script,E)),receiveDescriptorPriv:A?Le(Ye(h.script,A)):null,changeDescriptorPriv:C?Le(Ye(h.script,C)):null,receive:nn(s,b,h.script,t,f,"receive"),change:nn(s,b,h.script,t,f,"change")}});return{kind:"hd",network:t,mnemonic:null,passphraseUsed:!1,entropyHex:null,seedHex:null,rootXprv:i&&s.depth===0?s.privateExtendedKey??null:null,rootXpub:(s.depth===0,s.publicExtendedKey),masterFingerprint:a,notes:c,warnings:[...(i?[]:["Watch-only. Private keys are not in this key."]),`This extended key is not the BIP32 root. The imported node is reused directly; Account ${q} cannot select a different hardened sibling.`],accounts:d}}function $o(e){let t=e.trim();return!t.startsWith("S")||t.length!==22&&t.length!==30||!/^[A-Za-z0-9]+$/.test(t)?!1:Z(new TextEncoder().encode(t+"?"))[0]===0}function Ns(e){if(!$o(e))throw new Error("Not a valid Casascius mini private key.");return Z(new TextEncoder().encode(e.trim()))}function Io(e,t,r){let n=[],o=[],i,s=null,c=t,a=e.trim();if(r==="brain"){if(!a)throw new Error("Enter the brain-wallet passphrase.");o.push("Brain wallets are dangerous. Humans pick guessable phrases. Anyone who guesses the phrase takes the coins. Prefer dice or a hardware-verified seed."),i=Z(new TextEncoder().encode(a)),n.push("bitaddress.org-style brain wallet: SHA-256 of the passphrase is the private key.")}else if(r==="minikey"||$o(a))i=Ns(a),s=a,n.push("Casascius mini private key decoded via SHA-256.");else if(/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(a)){let E=Ls(a);i=E.priv,c=E.network,n.push(E.compressed?"Decoded a compressed WIF private key (starts with K or L on mainnet).":"Decoded an uncompressed WIF private key (starts with 5 on mainnet).")}else{let E=a.replace(/\s/g,"").replace(/^0x/i,"");if(!/^[0-9a-fA-F]{64}$/.test(E))throw new Error("Enter a WIF key (5/K/L\u2026), a 64-character hex private key, or a Casascius mini key (S\u2026).");i=M.decode(E.toLowerCase()),n.push("Decoded a 32-byte hex private key.")}hf(i);let f=Yr(i,!0),d=Yr(i,!1),h=_s(c),l=ir(d,h).address,u=ir(f,h).address,p=Jr(Tt(f,h),h).address,b=Tt(f,h).address,w=en(f.slice(1),void 0,h).address;return{kind:"single",network:c,warnings:o,notes:n,privHex:M.encode(i),wifCompressed:rn(i,!0,c),wifUncompressed:rn(i,!1,c),pubkeyCompressed:M.encode(f),pubkeyUncompressed:M.encode(d),p2pkhUncompressed:l,p2pkhCompressed:u,p2shP2wpkh:p,p2wpkh:b,p2tr:w,minikey:s}}function Oo(e,t){let r=[];if(r.push("ENTROPYLAB \u2014 RECOVERY SHEET"),r.push("This file was computed locally. The calculator never generated wallet entropy."),r.push(""),e.kind==="single"){r.push(`Network: ${e.network}`);for(let n of e.notes)r.push(`Note: ${n}`);for(let n of e.warnings)r.push(`Warning: ${n}`);return r.push(""),r.push("ADDRESSES"),r.push(`Legacy uncompressed: ${e.p2pkhUncompressed}`),r.push(`Legacy compressed:   ${e.p2pkhCompressed}`),r.push(`Nested SegWit:       ${e.p2shP2wpkh}`),r.push(`Native SegWit:       ${e.p2wpkh}`),r.push(`Taproot:             ${e.p2tr}`),r.push(`Compressed public key:   ${e.pubkeyCompressed}`),r.push(`Uncompressed public key: ${e.pubkeyUncompressed}`),t?(r.push(""),r.push("YOUR BITCOIN CORE PRIVATE KEY (WIF, compressed \u2014 use this with importprivkey)"),r.push(e.wifCompressed??""),r.push("WIF uncompressed: "+(e.wifUncompressed??"")),r.push("Hex private key:  "+(e.privHex??"")),e.minikey&&r.push("Mini key: "+e.minikey)):(r.push(""),r.push("Private keys hidden. Reveal them on an air-gapped computer.")),r.join(`
`)}r.push(`Network: ${e.network}`),r.push(`Master fingerprint: ${e.masterFingerprint}`),e.passphraseUsed&&r.push("Passphrase: YES (not printed)");for(let n of e.notes)r.push(`Note: ${n}`);for(let n of e.warnings)r.push(`Warning: ${n}`);r.push(""),e.mnemonic&&(r.push("YOUR SEED PHRASE"),r.push(e.mnemonic),r.push("")),t&&e.seedHex&&(r.push("MASTER SEED HEX (BIP39 PBKDF2, 512 bits)"),r.push(e.seedHex),r.push("")),t&&e.entropyHex&&(r.push("BIP39 ENTROPY HEX"),r.push(e.entropyHex),r.push("")),r.push("BIP32 ROOT XPUB"),r.push(e.rootXpub),t&&e.rootXprv&&(r.push("BIP32 ROOT XPRV"),r.push(e.rootXprv)),r.push("");for(let n of e.accounts){r.push(`=== ${n.def.label} (${n.def.bip}) ${hodlDisplayDerivationPath(n.accountPath)} ===`),r.push(n.def.beginner),r.push(`xpub: ${n.xpub}`),r.push(`ypub: ${n.ypub}`),r.push(`zpub: ${n.zpub}`),r.push(`vpub: ${n.vpub}`),t&&(n.xprv&&r.push(`xprv: ${n.xprv}`),n.yprv&&r.push(`yprv: ${n.yprv}`),n.zprv&&r.push(`zprv: ${n.zprv}`),n.vprv&&r.push(`vprv: ${n.vprv}`)),r.push(`Watch-only receive descriptor: ${n.receiveDescriptor}`),r.push(`Watch-only change descriptor:  ${n.changeDescriptor}`),t&&(n.receiveDescriptorPriv&&r.push(`Spending receive descriptor: ${n.receiveDescriptorPriv}`),n.changeDescriptorPriv&&r.push(`Spending change descriptor:  ${n.changeDescriptorPriv}`)),r.push("RECEIVE");for(let o of n.receive){let i=t&&o.wif?`  WIF ${o.wif}`:"";r.push(`  ${o.index}  ${hodlDisplayDerivationPath(o.path)}  ${o.address}${i}`)}r.push("CHANGE");for(let o of n.change){let i=t&&o.wif?`  WIF ${o.wif}`:"";r.push(`  ${o.index}  ${hodlDisplayDerivationPath(o.path)}  ${o.address}${i}`)}r.push("")}return r.join(`
`)}var ct=(e=>(e[e.Border=-1]="Border",e[e.Data=0]="Data",e[e.Function=1]="Function",e[e.Position=2]="Position",e[e.Timing=3]="Timing",e[e.Alignment=4]="Alignment",e))(ct||{}),xf=[0,1],zs=[1,0],Ds=[2,3],js=[3,2],Ef={L:xf,M:zs,Q:Ds,H:js},vf=/^\d*$/,kf=/^[A-Z0-9 $%*+./:-]*$/,_o="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:",Co=1,Ho=40,Fs=3,Bf=3,sn=40,Sf=10,Ks=[[-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],[-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],[-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],[-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]],Ws=[[-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],[-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],[-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],[-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]],Ro=class{constructor(t,r,n,o){g(this,"size");g(this,"mask");g(this,"modules",[]);g(this,"types",[]);if(this.version=t,this.ecc=r,t<Co||t>Ho)throw new RangeError("Version value out of range");if(o<-1||o>7)throw new RangeError("Mask value out of range");this.size=t*4+17;let i=Array.from({length:this.size}).fill(!1);for(let c=0;c<this.size;c++)this.modules.push(i.slice()),this.types.push(i.map(()=>0));this.drawFunctionPatterns();let s=this.addEccAndInterleave(n);if(this.drawCodewords(s),o===-1){let c=1e9;for(let a=0;a<8;a++){this.applyMask(a),this.drawFormatBits(a);let f=this.getPenaltyScore();f<c&&(o=a,c=f),this.applyMask(a)}}this.mask=o,this.applyMask(o),this.drawFormatBits(o)}getModule(t,r){return t>=0&&t<this.size&&r>=0&&r<this.size&&this.modules[r][t]}drawFunctionPatterns(){for(let n=0;n<this.size;n++)this.setFunctionModule(6,n,n%2===0,ct.Timing),this.setFunctionModule(n,6,n%2===0,ct.Timing);this.drawFinderPattern(3,3),this.drawFinderPattern(this.size-4,3),this.drawFinderPattern(3,this.size-4);let t=this.getAlignmentPatternPositions(),r=t.length;for(let n=0;n<r;n++)for(let o=0;o<r;o++)n===0&&o===0||n===0&&o===r-1||n===r-1&&o===0||this.drawAlignmentPattern(t[n],t[o]);this.drawFormatBits(0),this.drawVersion()}drawFormatBits(t){let r=this.ecc[1]<<3|t,n=r;for(let i=0;i<10;i++)n=n<<1^(n>>>9)*1335;let o=(r<<10|n)^21522;for(let i=0;i<=5;i++)this.setFunctionModule(8,i,Ce(o,i));this.setFunctionModule(8,7,Ce(o,6)),this.setFunctionModule(8,8,Ce(o,7)),this.setFunctionModule(7,8,Ce(o,8));for(let i=9;i<15;i++)this.setFunctionModule(14-i,8,Ce(o,i));for(let i=0;i<8;i++)this.setFunctionModule(this.size-1-i,8,Ce(o,i));for(let i=8;i<15;i++)this.setFunctionModule(8,this.size-15+i,Ce(o,i));this.setFunctionModule(8,this.size-8,!0)}drawVersion(){if(this.version<7)return;let t=this.version;for(let n=0;n<12;n++)t=t<<1^(t>>>11)*7973;let r=this.version<<12|t;for(let n=0;n<18;n++){let o=Ce(r,n),i=this.size-11+n%3,s=Math.floor(n/3);this.setFunctionModule(i,s,o),this.setFunctionModule(s,i,o)}}drawFinderPattern(t,r){for(let n=-4;n<=4;n++)for(let o=-4;o<=4;o++){let i=Math.max(Math.abs(o),Math.abs(n)),s=t+o,c=r+n;s>=0&&s<this.size&&c>=0&&c<this.size&&this.setFunctionModule(s,c,i!==2&&i!==4,ct.Position)}}drawAlignmentPattern(t,r){for(let n=-2;n<=2;n++)for(let o=-2;o<=2;o++)this.setFunctionModule(t+o,r+n,Math.max(Math.abs(o),Math.abs(n))!==1,ct.Alignment)}setFunctionModule(t,r,n,o=ct.Function){this.modules[r][t]=n,this.types[r][t]=o}addEccAndInterleave(t){let r=this.version,n=this.ecc;if(t.length!==cn(r,n))throw new RangeError("Invalid argument");let o=Ws[n[0]][r],i=Ks[n[0]][r],s=Math.floor(Uo(r)/8),c=o-s%o,a=Math.floor(s/o),f=[],d=Uf(i);for(let l=0,u=0;l<o;l++){let p=t.slice(u,u+a-i+(l<c?0:1));u+=p.length;let b=Lf(p,d);l<c&&p.push(0),f.push(p.concat(b))}let h=[];for(let l=0;l<f[0].length;l++)f.forEach((u,p)=>{(l!==a-i||p>=c)&&h.push(u[l])});return h}drawCodewords(t){if(t.length!==Math.floor(Uo(this.version)/8))throw new RangeError("Invalid argument");let r=0;for(let n=this.size-1;n>=1;n-=2){n===6&&(n=5);for(let o=0;o<this.size;o++)for(let i=0;i<2;i++){let s=n-i,a=(n+1&2)===0?this.size-1-o:o;!this.types[a][s]&&r<t.length*8&&(this.modules[a][s]=Ce(t[r>>>3],7-(r&7)),r++)}}}applyMask(t){if(t<0||t>7)throw new RangeError("Mask value out of range");for(let r=0;r<this.size;r++)for(let n=0;n<this.size;n++){let o;switch(t){case 0:o=(n+r)%2===0;break;case 1:o=r%2===0;break;case 2:o=n%3===0;break;case 3:o=(n+r)%3===0;break;case 4:o=(Math.floor(n/3)+Math.floor(r/2))%2===0;break;case 5:o=n*r%2+n*r%3===0;break;case 6:o=(n*r%2+n*r%3)%2===0;break;case 7:o=((n+r)%2+n*r%3)%2===0;break;default:throw new Error("Unreachable")}!this.types[r][n]&&o&&(this.modules[r][n]=!this.modules[r][n])}}getPenaltyScore(){let t=0;for(let i=0;i<this.size;i++){let s=!1,c=0,a=[0,0,0,0,0,0,0];for(let f=0;f<this.size;f++)this.modules[i][f]===s?(c++,c===5?t+=Fs:c>5&&t++):(this.finderPenaltyAddHistory(c,a),s||(t+=this.finderPenaltyCountPatterns(a)*sn),s=this.modules[i][f],c=1);t+=this.finderPenaltyTerminateAndCount(s,c,a)*sn}for(let i=0;i<this.size;i++){let s=!1,c=0,a=[0,0,0,0,0,0,0];for(let f=0;f<this.size;f++)this.modules[f][i]===s?(c++,c===5?t+=Fs:c>5&&t++):(this.finderPenaltyAddHistory(c,a),s||(t+=this.finderPenaltyCountPatterns(a)*sn),s=this.modules[f][i],c=1);t+=this.finderPenaltyTerminateAndCount(s,c,a)*sn}for(let i=0;i<this.size-1;i++)for(let s=0;s<this.size-1;s++){let c=this.modules[i][s];c===this.modules[i][s+1]&&c===this.modules[i+1][s]&&c===this.modules[i+1][s+1]&&(t+=Bf)}let r=0;for(let i of this.modules)r=i.reduce((s,c)=>s+(c?1:0),r);let n=this.size*this.size,o=Math.ceil(Math.abs(r*20-n*10)/n)-1;return t+=o*Sf,t}getAlignmentPatternPositions(){if(this.version===1)return[];{let t=Math.floor(this.version/7)+2,r=this.version===32?26:Math.ceil((this.version*4+4)/(t*2-2))*2,n=[6];for(let o=this.size-7;n.length<t;o-=r)n.splice(1,0,o);return n}}finderPenaltyCountPatterns(t){let r=t[1],n=r>0&&t[2]===r&&t[3]===r*3&&t[4]===r&&t[5]===r;return(n&&t[0]>=r*4&&t[6]>=r?1:0)+(n&&t[6]>=r*4&&t[0]>=r?1:0)}finderPenaltyTerminateAndCount(t,r,n){return t&&(this.finderPenaltyAddHistory(r,n),r=0),r+=this.size,this.finderPenaltyAddHistory(r,n),this.finderPenaltyCountPatterns(n)}finderPenaltyAddHistory(t,r){r[0]===0&&(t+=this.size),r.pop(),r.unshift(t)}};function He(e,t,r){if(t<0||t>31||e>>>t)throw new RangeError("Value out of range");for(let n=t-1;n>=0;n--)r.push(e>>>n&1)}function Ce(e,t){return(e>>>t&1)!==0}var fr=class{constructor(t,r,n){if(this.mode=t,this.numChars=r,this.bitData=n,r<0)throw new RangeError("Invalid argument");this.bitData=n.slice()}getData(){return this.bitData.slice()}},Tf=[1,10,12,14],Af=[2,9,11,13],Pf=[4,8,16,16];function qs(e,t){return e[Math.floor((t+7)/17)+1]}function Vs(e){let t=[];for(let r of e)He(r,8,t);return new fr(Pf,e.length,t)}function $f(e){if(!Ys(e))throw new RangeError("String contains non-numeric characters");let t=[];for(let r=0;r<e.length;){let n=Math.min(e.length-r,3);He(Number.parseInt(e.substring(r,r+n),10),n*3+1,t),r+=n}return new fr(Tf,e.length,t)}function If(e){if(!Gs(e))throw new RangeError("String contains unencodable characters in alphanumeric mode");let t=[],r;for(r=0;r+2<=e.length;r+=2){let n=_o.indexOf(e.charAt(r))*45;n+=_o.indexOf(e.charAt(r+1)),He(n,11,t)}return r<e.length&&He(_o.indexOf(e.charAt(r)),6,t),new fr(Af,e.length,t)}function Of(e){return e===""?[]:Ys(e)?[$f(e)]:Gs(e)?[If(e)]:[Vs(Rf(e))]}function Ys(e){return vf.test(e)}function Gs(e){return kf.test(e)}function _f(e,t){let r=0;for(let n of e){let o=qs(n.mode,t);if(n.numChars>=1<<o)return Number.POSITIVE_INFINITY;r+=4+o+n.bitData.length}return r}function Rf(e){e=encodeURI(e);let t=[];for(let r=0;r<e.length;r++)e.charAt(r)!=="%"?t.push(e.charCodeAt(r)):(t.push(Number.parseInt(e.substring(r+1,r+3),16)),r+=2);return t}function Uo(e){if(e<Co||e>Ho)throw new RangeError("Version number out of range");let t=(16*e+128)*e+64;if(e>=2){let r=Math.floor(e/7)+2;t-=(25*r-10)*r-55,e>=7&&(t-=36)}return t}function cn(e,t){return Math.floor(Uo(e)/8)-Ks[t[0]][e]*Ws[t[0]][e]}function Uf(e){if(e<1||e>255)throw new RangeError("Degree out of range");let t=[];for(let n=0;n<e-1;n++)t.push(0);t.push(1);let r=1;for(let n=0;n<e;n++){for(let o=0;o<t.length;o++)t[o]=Lo(t[o],r),o+1<t.length&&(t[o]^=t[o+1]);r=Lo(r,2)}return t}function Lf(e,t){let r=t.map(n=>0);for(let n of e){let o=n^r.shift();r.push(0),t.forEach((i,s)=>r[s]^=Lo(i,o))}return r}function Lo(e,t){if(e>>>8||t>>>8)throw new RangeError("Byte out of range");let r=0;for(let n=7;n>=0;n--)r=r<<1^(r>>>7)*285,r^=(t>>>n&1)*e;return r}function Cf(e,t,r=1,n=40,o=-1,i=!0){if(!(Co<=r&&r<=n&&n<=Ho)||o<-1||o>7)throw new RangeError("Invalid value");let s,c;for(s=r;;s++){let h=cn(s,t)*8,l=_f(e,s);if(l<=h){c=l;break}if(s>=n)throw new RangeError("Data too long")}for(let h of[zs,Ds,js])i&&c<=cn(s,h)*8&&(t=h);let a=[];for(let h of e){He(h.mode[0],4,a),He(h.numChars,qs(h.mode,s),a);for(let l of h.getData())a.push(l)}let f=cn(s,t)*8;He(0,Math.min(4,f-a.length),a),He(0,(8-a.length%8)%8,a);for(let h=236;a.length<f;h^=253)He(h,8,a);let d=Array.from({length:Math.ceil(a.length/8)},()=>0);return a.forEach((h,l)=>d[l>>>3]|=h<<7-(l&7)),new Ro(s,t,d,o)}function Hf(e,t){let{ecc:r="L",boostEcc:n=!1,minVersion:o=1,maxVersion:i=40,maskPattern:s=-1,border:c=1}=t||{},a=typeof e=="string"?Of(e):Array.isArray(e)?[Vs(e)]:void 0;if(!a)throw new Error(`uqr only supports encoding string and binary data, but got: ${typeof e}`);let f=Cf(a,Ef[r],o,i,s,n),d=Nf({version:f.version,maskPattern:f.mask,size:f.size,data:f.modules,types:f.types},c);return t?.invert&&(d.data=d.data.map(h=>h.map(l=>!l))),t?.onEncoded?.(d),d}function Nf(e,t=1){if(!t)return e;let{size:r}=e,n=r+t*2;e.size=n,e.data.forEach(i=>{for(let s=0;s<t;s++)i.unshift(!1),i.push(!1)});for(let i=0;i<t;i++)e.data.unshift(Array.from({length:n},s=>!1)),e.data.push(Array.from({length:n},s=>!1));let o=ct.Border;e.types.forEach(i=>{for(let s=0;s<t;s++)i.unshift(o),i.push(o)});for(let i=0;i<t;i++)e.types.unshift(Array.from({length:n},s=>o)),e.types.push(Array.from({length:n},s=>o));return e}function Ms(e){return e.replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function Xs(e,t={}){let r=Hf(e,t),{pixelSize:n=10,whiteColor:o="white",blackColor:i="black"}=t,s=r.size*n,c=r.size*n,a=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${c} ${s}">`,f=[];for(let d=0;d<r.size;d++)for(let h=0;h<r.size;h++){let l=h*n,u=d*n;r.data[d][h]&&f.push(`M${l},${u}h${n}v${n}h-${n}z`)}return a+=`<rect fill="${Ms(o)}" width="${c}" height="${s}"/>`,a+=`<path fill="${Ms(i)}" d="${f.join("")}"/>`,a+="</svg>",a}function an(e,t="#111111",r="#ffffff"){return Xs(e,{ecc:"M",border:2,pixelSize:4,blackColor:t,whiteColor:r})}var ec=document.getElementById("btc-calc");if(!ec)throw new Error("#app missing");ec.innerHTML=`
  <div class="wrap">
    <aside class="beta-warning no-print" role="alert">
      <strong>Beta software:</strong> EntropyLab is experimental and should be used only for testing. Do not rely on it to secure real bitcoin, and never test with funds you cannot afford to lose.
    </aside>
    <aside class="online-warning no-print" id="online-warning" role="alert" hidden>
      <strong>Online version:</strong> Do not enter seed phrases, private keys, or other wallet secrets on an internet-connected device. <a href="entropylab-{{VERSION}}.html" download="entropylab-{{VERSION}}.html">Download EntropyLab</a> and run the HTML file offline on a trusted, air-gapped computer.
    </aside>
    <aside class="network-warning no-print" id="network-warning" role="alert" hidden>
      <strong>Network detected:</strong> This computer has an active network adapter — it is online and possibly connected to the internet. Do not enter wallet secrets here; disconnect from all networks (Wi-Fi and Ethernet) and use this file on an air-gapped computer.
    </aside>
    <header>
      <div>
        <div class="kicker">EntropyLab v{{VERSION}} \xB7 Run Offline \xB7 No entropy RNG \xB7 Bring your own entropy</div>
        <div class="header-title-row"><img class="online-brand-mark" id="online-brand-mark" data-online-src="assets/entropylab_dark.png" alt="" aria-hidden="true" hidden><h1>EntropyLab — Air-Gapped Bitcoin Calculator</h1></div>
        <p class="muted">This file never generates wallet entropy. Save it to USB and open it on a computer that never goes online.</p>
        <div class="download-controls no-print">
          <label class="version-picker">Version
            <select class="version-select" aria-label="EntropyLab version"><option value="entropylab-{{VERSION}}.html" selected>v{{VERSION}} (Latest)</option></select>
          </label>
          <a class="btn secondary download-html" href="entropylab-{{VERSION}}.html" download="entropylab-{{VERSION}}.html">Download EntropyLab</a>
          <a class="btn secondary github-repo-link" href="https://github.com/w-s-bitcoin/entropylab" target="_blank" rel="noopener noreferrer" aria-label="View the EntropyLab GitHub repository in a new tab">View on GitHub</a>
        </div>
      </div>
    </header>
    <section class="card">
      <div class="kicker">Hold first. Sign later.</div>
      <h2>You do not need a signing device to hold or receive bitcoin.</h2>
      <p class="muted">A signing device is only required when you spend. Turn dice rolls or a seed you already have into receive addresses, load the xpub into Bitcoin Core or any watch-only wallet, and get paid. Keep the seed on this air-gapped machine. Carry only addresses and the xpub online.</p>
    </section>
    <div class="row no-print segmented-control" id="workspace" role="group" aria-label="Workspace"></div>
    <section class="key-manager no-print" id="key-manager">
      <div class="key-manager-head"><h2>Keys</h2><div class="add-item-control"><button class="btn secondary add-key" id="add-key" type="button" aria-label="Add key" aria-describedby="add-key-tooltip">+</button><span class="add-item-tooltip" id="add-key-tooltip" role="tooltip">Add another key</span></div></div>
      <div class="key-tabs" id="key-tabs" role="tablist" aria-label="Keys"></div>
    </section>
    <section class="card no-print" id="calc-card" role="tabpanel" hidden>
      <div class="key-panel-head">
        <div class="row segmented-control" id="modes" role="group" aria-label="Key input mode"></div>
        <button class="btn delete-key" id="delete-key" type="button" aria-label="Delete current key" disabled>Delete Key</button>
      </div>
      <section class="seed-length-control" id="seed-length" aria-labelledby="seed-length-label">
        <p class="label" id="seed-length-label">Seed phrase length</p>
        <div class="row seed-length-options segmented-control" role="group" aria-label="Seed phrase length">
          <button type="button" class="tab" data-seed-words="12" aria-pressed="false">12 words</button>
          <button type="button" class="tab" data-seed-words="18" aria-pressed="false">18 words</button>
          <button type="button" class="tab active" data-seed-words="24" aria-pressed="true">24 words</button>
        </div>
        <p class="muted" id="seed-length-help">24 words use 256 bits of BIP39 entropy.</p>
      </section>
      <div id="form" class="key-form"></div>
      <label class="field" id="passphrase-field">Optional BIP39 passphrase
        <input id="pass" autocomplete="off" placeholder="Leave blank unless you set one" />
      </label>
      <div class="master-fingerprint-preview" id="master-fingerprint-preview" role="status" aria-live="polite" aria-atomic="true">
        <div class="master-fingerprint-card is-disabled" id="base-master-fingerprint-card" role="group" data-state="unavailable" aria-label="Base seed Master Fingerprint unavailable">
          <span class="master-fingerprint-label">Base seed · Master Fingerprint</span>
          <code class="master-fingerprint-value" id="base-master-fingerprint"></code>
        </div>
        <span class="master-fingerprint-arrow is-disabled" id="master-fingerprint-arrow" aria-hidden="true">\u2192</span>
        <div class="master-fingerprint-card master-fingerprint-derived is-disabled" id="passphrase-master-fingerprint-card" role="group" data-state="unavailable" aria-label="With passphrase Master Fingerprint unavailable">
          <span class="master-fingerprint-label">With passphrase · Master Fingerprint</span>
          <code class="master-fingerprint-value" id="passphrase-master-fingerprint"></code>
        </div>
      </div>
      <div class="key-settings" id="key-settings">
        <div class="key-settings-row">
          <label class="field" id="script-type-field">Script type
            <select id="script-type"><option value="bip44">Legacy · BIP44</option><option value="bip49">Nested SegWit · BIP49</option><option value="bip84" selected>Native SegWit · BIP84</option><option value="bip86">Taproot · BIP86</option></select>
          </label>
          <label class="field network-field">Network
            <select id="network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
          </label>
        </div>
        <div class="key-settings-row" id="account-address-settings">
          <label class="field">Account
            <input id="account" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="0" aria-describedby="account-help">
            <span class="field-note" id="account-help">Hardened account index · 0 to 2,147,483,647</span>
          </label>
          <label class="field">Addresses
            <select id="count"><option value="5">5 receive + 5 change</option><option value="10">10 receive + 10 change</option><option value="20">20 receive + 20 change</option></select>
          </label>
        </div>
      </div>
      <section class="derivation-path-preview" id="derivation-path-preview" aria-labelledby="derivation-path-heading" aria-live="polite">
        <div class="derivation-path-head"><p class="label" id="derivation-path-heading">Derivation paths</p><span class="derivation-path-context" id="derivation-path-context"></span></div>
        <dl class="derivation-path-list">
          <div class="derivation-path-row"><dt>Account</dt><dd><code data-path="account"></code></dd></div>
          <div class="derivation-path-row"><dt>Receive</dt><dd><code data-path="receive"></code></dd></div>
          <div class="derivation-path-row"><dt>Change</dt><dd><code data-path="change"></code></dd></div>
        </dl>
        <p class="derivation-path-error" id="derivation-path-error" hidden></p>
      </section>
      <div class="row key-action-row current-item-actions">
        <button class="btn primary" id="go" disabled aria-disabled="true">Derive Wallet</button>
        <button class="btn clear-current-action" id="wipe" type="button" disabled aria-disabled="true">Clear Current Key</button>
      </div>
      <p class="err" id="error"></p>
    </section>
    <section class="key-manager no-print" id="msig-manager" hidden>
      <div class="key-manager-head"><h2>Multisigs</h2><div class="add-item-control"><button class="btn secondary add-key" id="add-msig" type="button" aria-label="Add multisig" aria-describedby="add-msig-tooltip">+</button><span class="add-item-tooltip" id="add-msig-tooltip" role="tooltip">Add another multisig</span></div></div>
      <div class="key-tabs" id="msig-tabs" role="tablist" aria-label="Multisigs"></div>
    </section>
    <section class="card no-print" id="msig-card" role="tabpanel" hidden>
      <div class="key-panel-head">
        <div><div class="kicker">Multiple keys, one wallet</div><h2>Derive a multisig wallet</h2></div>
        <button class="btn delete-key" id="delete-msig" type="button" aria-label="Delete current multisig" disabled>Delete Multisig</button>
      </div>
      <p class="muted msig-intro">Combine extended public keys into a multisignature wallet. Paste each key origin and extended public key as exported by its signer: <span class="mono">[fingerprint/48h/0h/0h/2h]xpub…</span>. Private keys are not needed. The derived addresses can receive bitcoin, and spending requires the configured number of signatures.</p>
      <fieldset class="msig-threshold-control">
        <legend class="sr-only">Multisig signature threshold</legend>
        <div class="msig-threshold-labels">
          <label for="msig-m-number"><span>Signatures needed to spend (m)</span><input class="msig-threshold-number" id="msig-m-number" type="number" min="1" max="15" step="1" value="2" inputmode="numeric" aria-describedby="msig-threshold-help"></label>
          <label for="msig-n-number"><span>Total signing keys (n)</span><input class="msig-threshold-number" id="msig-n-number" type="number" min="1" max="15" step="1" value="3" inputmode="numeric" aria-describedby="msig-threshold-help"></label>
        </div>
        <div class="msig-threshold-slider" id="msig-threshold-slider" style="--msig-m-position:12.5%;--msig-n-position:25%" data-slider-max="9">
          <div class="msig-threshold-track" aria-hidden="true"><span></span></div>
          <span class="msig-threshold-thumb msig-threshold-thumb-m" aria-hidden="true"></span>
          <span class="msig-threshold-thumb msig-threshold-thumb-n" aria-hidden="true"></span>
          <input class="msig-threshold-range" id="msig-m" type="range" min="1" max="15" step="1" value="2" aria-label="Signatures needed to spend (m)" aria-describedby="msig-threshold-help">
          <input class="msig-threshold-range" id="msig-n" type="range" min="1" max="15" step="1" value="3" aria-label="Total signing keys (n)" aria-describedby="msig-threshold-help">
        </div>
        <div class="msig-threshold-ticks" id="msig-threshold-ticks" aria-hidden="true"><span style="--msig-tick-position:0%">1</span><span style="--msig-tick-position:12.5%">2</span><span style="--msig-tick-position:25%">3</span><span style="--msig-tick-position:37.5%">4</span><span style="--msig-tick-position:50%">5</span><span style="--msig-tick-position:62.5%">6</span><span style="--msig-tick-position:75%">7</span><span style="--msig-tick-position:87.5%">8</span><span style="--msig-tick-position:100%">9</span></div>
        <p class="field-note msig-threshold-help" id="msig-threshold-help">Enter values, drag either handle, or use the arrow keys. Editing one value past the other moves both.</p>
      </fieldset>
      <div id="msig-keys" class="msig-keys"></div>
      <p class="hint" id="msig-hint"></p>
      <div class="key-settings msig-output-settings">
        <label class="choice msig-legacy-account-toggle" id="msig-legacy-account-toggle" hidden>
          <input id="msig-legacy-bip87" type="checkbox" aria-describedby="msig-legacy-bip87-help">
          <span><strong>Use standardized BIP87 accounts</strong><span class="desc" id="msig-legacy-bip87-help">Uses <span class="mono">m/87h/coinh/accounth</span> with this Legacy P2SH descriptor. BIP87 account keys are script-agnostic. Leave unchecked for default BIP45 without accounts.</span></span>
        </label>
        <div class="key-settings-row">
          <label class="field">Script type
            <select id="msig-script-type" aria-describedby="msig-script-warning"><option value="p2sh">Legacy · BIP45</option><option value="p2sh-p2wsh">Nested SegWit · BIP48</option><option value="p2wsh" selected>Native SegWit · BIP48</option><option value="mixed" disabled data-custom-select-placeholder="true">Mixed · incompatible keys</option></select>
            <span class="field-note msig-script-warning" id="msig-script-warning" role="status" hidden></span>
          </label>
          <label class="field">Network
            <select id="msig-network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
          </label>
        </div>
        <div class="key-settings-row">
          <label class="field">Account
            <input id="msig-account" type="text" value="" placeholder="Derived from keys" disabled aria-describedby="msig-account-help msig-account-warning">
            <span class="field-note" id="msig-account-help">Derived from co-signer key origins.</span>
            <span class="field-note msig-account-warning" id="msig-account-warning" role="status" hidden></span>
          </label>
          <label class="field">Addresses
            <select id="msig-count"><option value="5">5 + 5</option><option value="10">10 + 10</option><option value="20">20 + 20</option></select>
          </label>
        </div>
      </div>
      <div class="row current-item-actions">
        <button class="btn primary" id="msig-go" type="button" aria-describedby="msig-script-warning" disabled aria-disabled="true">Derive Multisig</button>
        <button class="btn clear-current-action" id="msig-wipe" type="button" disabled aria-disabled="true">Clear Current Multisig</button>
      </div>
      <p class="err" id="msig-error"></p>
    </section>
    <section class="card no-print" id="psbt-card" role="tabpanel" hidden>
      <div class="kicker">Inspect first. Sign elsewhere.</div>
      <h2>Read a PSBT. Check its ECDSA nonces.</h2>
      <p class="muted psbt-intro">Inspecting a PSBT v0 does not require a private key. EntropyLab can show outputs, PSBT-provided input amounts and fees, signatures, and repeated ECDSA nonce values. Loading a matching key additionally checks whether supported signatures match plain RFC 6979; a mismatch alone is not evidence of a compromised signer.</p>
      <label class="field">PSBT v0 (base64 or hex)
        <textarea id="psbt-text" placeholder="cHNidP8B..." spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
      </label>
      <div class="psbt-grid">
        <label class="field">Optional session key (BIP39 seed phrase, WIF, or 64-character hex)
          <textarea id="psbt-key" placeholder="Leave blank for inspect-only mode" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
        </label>
        <div>
          <label class="field">Optional BIP39 passphrase
            <input id="psbt-pass" autocomplete="off" placeholder="Leave blank unless you set one">
          </label>
          <label class="field">Address network
            <select id="psbt-network"><option value="mainnet" selected>Bitcoin mainnet</option><option value="testnet">Testnet (practice)</option></select>
          </label>
        </div>
      </div>
      <div class="row psbt-actions">
        <button class="btn primary" id="psbt-go" type="button">Inspect PSBT</button>
        <button class="btn secondary" id="psbt-use-calc" type="button">Use active key this session</button>
        <button class="btn secondary" id="psbt-wipe" type="button">End session / clear fields</button>
      </div>
      <p class="muted" id="psbt-session" aria-live="polite">No session key. Inspect-only mode.</p>
      <p class="err" id="psbt-error" role="alert"></p>
      <div id="psbt-out" aria-live="polite"></div>
      <p class="muted">Session keys remain in this page only and are never intentionally stored or sent. Memory clearing is best-effort because browsers may retain internal copies; close the page before reconnecting the computer.</p>
    </section>
    <div id="out"></div>
    <section class="card muted">
      <h3 class="sources-heading">Sources</h3>
      <p>Ian Coleman BIP39: <a href="https://github.com/iancoleman/bip39">github.com/iancoleman/bip39</a> \u2014 pull <code>bip39-standalone.html</code> from Releases, or <code>src/js/index.js</code>, <code>entropy.js</code>, <code>jsbip39.js</code>, <code>wordlist_english.js</code>.</p>
      <p>bitaddress.org: <a href="https://github.com/pointbiz/bitaddress.org">github.com/pointbiz/bitaddress.org</a> \u2014 pull <code>bitaddress.org.html</code>, or <code>src/ninja.key.js</code>, <code>ninja.detailwallet.js</code>, <code>ninja.paperwallet.js</code>, <code>bitcoinjs-lib.eckey.js</code>.</p>
      <p>BitBox02 diceware: <a href="https://blog.bitbox.swiss/en/roll-the-dice-generate-your-own-seed/">roll-the-dice-generate-your-own-seed</a> \u2014 lookup table is the BIP39 English list in order.</p>
      <p>D++ D8 &amp; D16 method: <a href="https://thesimplestbitcoinbook.net/wp-content/uploads/2023/09/Roll-Your-Own-Seed-Phrase-PDF.pdf">Roll Your Own Bitcoin Seed Phrase</a> \u2014 the published 24-word workflow uses one D8 and two D16 rolls per word, then a final D8.</p>
    </section>
  </div>
`;if(/^(www\.)?entropylab\.online$/i.test(location.hostname))document.getElementById("online-warning")?.removeAttribute("hidden");var Ne="dice",ge="coldcard",Pt=24,hodlEntropyFormat="hex",hodlDiceCoinPositions=[],hodlDPlusNumberedD16=!1,hodlPadShuffle=!1,ft="",re=null,Ge=!1,Zs=W("#modes"),at=W("#form"),dr=W("#out");["dice","hex","seed","key"].forEach(e=>{let t=document.createElement("button"),active=e===Ne;t.type="button";t.className="tab"+(active?" active":"");t.setAttribute("aria-pressed",String(active));t.textContent=e==="dice"?"Dice rolls":e==="hex"?"Hex or binary":e==="seed"?"Seed phrase":"Private key";t.onclick=()=>hodlSetMode(e);Zs.appendChild(t)});document.querySelectorAll("#seed-length [data-seed-words]").forEach(button=>{button.onclick=()=>hodlSetSeedLength(Number(button.dataset.seedWords))});W("#go").onclick=hodlCalculateKey;W("#wipe").onclick=hodlWipeActiveKey;function W(e){let t=e.startsWith("#")?e.slice(1):e,r=document.getElementById(t);if(!r)throw new Error(t);return r}function lr(){if(Ne==="dice"){at.innerHTML=`
      <p class="label">How to turn rolls into a seed</p>
      <label class="choice"><input type="radio" name="dm" value="coldcard" ${ge==="coldcard"?"checked":""} />
        <span><strong>Hashed rolls / Base 10 [0-9] (recommended)</strong>
        <span class="desc">SHA-256 of the original dice digit string, matching the method used by COLDCARD and SeedSigner. Every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="bitbox" ${ge==="bitbox"?"checked":""} />
        <span><strong>BitBox diceware / Direct word selection</strong>
        <span class="desc">Same as the BitBox02 lookup table: five dice showing 1\u20134, then a coin (or 6th die: 1\u20133 heads, 4\u20136 tails). 5 and 6 on the first five dice of a word are skipped (reroll). After 23 words, pick one of the 8 checksum words.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="coleman" ${ge==="coleman"?"checked":""} />
        <span><strong>Hashed rolls / Dice [1-6]</strong>
        <span class="desc">Convert every 6 to 0, then SHA-256 hash the complete mapped digit string, matching the method used by Keystone.</span></span>
      </label>
      <div id="bitbox-extra" ${ge==="bitbox"?"":"hidden"}>
        <div class="row" style="margin-top:12px">
          <button type="button" class="tab${Pt===24?" active":""}" data-bt="24">24 words</button>
          <button type="button" class="tab${Pt===12?" active":""}" data-bt="12">12 words</button>
        </div>
      </div>
      <p class="label" id="dice-label">${ge==="bitbox"?"Dice rolls (1\u20134, then coin / 6th die)":"Dice rolls (faces 1\u20136 only)"}</p>
      <p class="muted" id="dice-help">${ge==="bitbox"?`${Pt===24?23:11} lookup-table words, then a checksum pick. Type rolls, tap 1\u20134, then Heads/Tails (or 1\u20133 / 4\u20136).`:ge==="coleman"?"Every 6 becomes 0 before SHA-256 hashing, matching the method used by Keystone.":"SHA-256 hashes the original digit string, matching the Base 10 [0-9] method used by COLDCARD and SeedSigner."}</p>
      <div class="dice-input-shell"><pre class="dice-input-highlight" id="dice-highlight" aria-hidden="true"></pre><textarea id="dice" placeholder="${ge==="bitbox"?"111111222224\u2026":"e.g. 415263415263\u2026"}" aria-describedby="dice-help dice-meta"></textarea></div>
      <div class="dice-input-pad with-coin">${[1,3,5].map(t=>`<button type="button" data-d="${t}">${t}</button>`).join("")}<button type="button" class="coin-button" data-d="H" data-coin="heads">Heads (1\u20133)</button>${[2,4,6].map(t=>`<button type="button" data-d="${t}">${t}</button>`).join("")}<button type="button" class="coin-button" data-d="T" data-coin="tails">Tails (4\u20136)</button></div>
      <p class="muted" id="dice-meta"></p>
      <div id="bitbox-words" class="wordlist"></div>
      <div id="last-words" class="row" style="margin-top:8px"></div>
    `;let e=document.getElementById("dice");e.dataset.previousValue=e.value;at.querySelectorAll("[data-d]").forEach(t=>{t.onclick=()=>hodlInsertDiceControl(e,t,At)}),e.oninput=()=>{hodlTrackDiceInputEdit(e);hodlSanitizeDiceInput(e);At()},e.onscroll=()=>hodlSyncDiceHighlight(e),at.querySelectorAll("input[name=dm]").forEach(t=>{t.onchange=()=>{ge=t.value,ft="";let r=e.value;lr();let n=document.getElementById("dice");n&&(n.value=r,n.dataset.previousValue=r,n.setSelectionRange(r.length,r.length)),At()}}),at.querySelectorAll("[data-bt]").forEach(t=>{t.onclick=()=>{Pt=Number(t.dataset.bt)===12?12:24,ft="";let r=e.value;lr();let n=document.getElementById("dice");n&&(n.value=r,n.dataset.previousValue=r,n.setSelectionRange(r.length,r.length)),At()}}),At();hodlBindFields()}else if(Ne==="hex"){at.innerHTML=`
      <p class="label">Hexadecimal entropy</p>
      <p class="muted">32 hex characters = 12 words. 64 hex characters = 24 words. No generator \u2014 paste what you already rolled, hashed, or wrote down.</p>
      <textarea id="hex" placeholder="64 hex characters for a 24-word seed"></textarea>
      <p class="label">Or binary (coin flips)</p>
      <textarea id="bin" placeholder="At least 128 zeros and ones"></textarea>
    `;hodlBindFields()}else if(Ne==="seed"){at.innerHTML=`
      <p class="label">Your seed phrase</p>
      <p class="muted">12 or 24 English BIP39 words. You can also paste an xprv / xpub / zpub here. If you have 23 words from BitBox diceware, paste them and pick the checksum word below.</p>
      <textarea id="seed" placeholder="word1 word2 word3 \u2026"></textarea>
      <p class="muted" id="seed-meta"></p>
      <div id="last-words" class="row" style="margin-top:8px"></div>
    `;let e=document.getElementById("seed"),t=()=>{let r=Mt(e.value),n=Tr(e.value);n&&!n.error?(W("#seed-meta").textContent=n.partialCount===23?"BitBox-style: pick the 24th checksum word":`${n.candidates.length} valid last words \u2014 type the one you confirmed on the device, then Calculate`,W("#seed-meta").className="muted ok",n.candidates.length<=16?(W("#last-words").innerHTML=n.candidates.map(o=>`<button type="button" class="tab" data-lw="${o}">${o}</button>`).join(" "),W("#last-words").querySelectorAll("[data-lw]").forEach(o=>{o.onclick=()=>{e.value=`${e.value.trim()} ${o.dataset.lw}`,t()}})):W("#last-words").innerHTML=""):(W("#last-words").innerHTML="",W("#seed-meta").textContent=e.value.trim()?r.ok?`${r.words.length} words, checksum valid`:r.error??"":"",W("#seed-meta").className="muted "+(r.ok?"ok":"err"))};e.oninput=()=>{e.value=hodlFilterSeed(e.value);t()};hodlBindFields();}else at.innerHTML=`
      <p class="label">Your Bitcoin Core private key</p>
      <p class="muted">WIF, hex, mini key, or a brain-wallet passphrase (unsafe \u2014 recovery only).</p>
      <textarea id="key" placeholder="K\u2026 / L\u2026 / 5\u2026 / hex"></textarea>
      <label class="choice"><input type="radio" name="kk" value="wif-or-hex" checked /><span><strong>WIF / hex</strong><span class="desc">Normal Bitcoin Core private key.</span></span></label>
      <label class="choice"><input type="radio" name="kk" value="minikey" /><span><strong>Mini key</strong><span class="desc">Casascius-style short key.</span></span></label>
      <label class="choice"><input type="radio" name="kk" value="brain" /><span><strong>Brain wallet</strong><span class="desc">Unsafe. Use only to recover an old passphrase wallet.</span></span></label>
    `;hodlBindFields()}function At(){let e=document.getElementById("dice");if(!e)return;hodlRenderDiceInputState(e);let t=document.getElementById("bitbox-words"),r=document.getElementById("last-words");if(ge==="bitbox"){let o=Sr(e.value,Pt),i=o.waiting==="last-word"?`${o.words.length} words \xB7 pick the checksum word`:o.waiting==="coin"?`Word ${o.words.length+1} of ${o.neededPartial} \xB7 coin / 6th die`:`Word ${o.words.length+1} of ${o.neededPartial} \xB7 die ${o.diceInWord+1} of 5 (faces 1\u20134)`;W("#dice-meta").textContent=i,t&&(t.innerHTML=o.words.length?o.words.map((c,a)=>`<div><span>${a+1}.</span>${c}</div>`).join(""):"");let s=o.waiting==="last-word"?Tr(o.words.join(" ")):null;r&&s&&!s.error&&s.candidates.length<=16?(r.innerHTML=s.candidates.map(c=>`<button type="button" class="tab${c===ft?" active":""}" data-lw="${c}">${c}</button>`).join(""),r.querySelectorAll("[data-lw]").forEach(c=>{c.onclick=()=>{ft=c.dataset.lw??"",At()}})):r&&(r.innerHTML="");return}t&&(t.innerHTML=""),r&&(r.innerHTML="");let{rolls:n}=Br(e.value);W("#dice-meta").textContent=`${n.length} rolls \xB7 ${kr(n.length).toFixed(1)} bits \xB7 99 rolls for 256-bit 24-word seed`;hodlDiceCompare()}function Ff(){W("#error").textContent="";try{let e=document.getElementById("network").value,t=Number(document.getElementById("count").value),r=document.getElementById("pass").value;if(Ne==="dice")if(ge==="bitbox"){let n=Sr(document.getElementById("dice").value,Pt);if(n.leftover)throw new Error(`Invalid characters: ${n.leftover}`);if(n.waiting!=="last-word")throw new Error(`Need ${n.neededPartial} lookup-table words. You have ${n.words.length}.`);if(!ft)throw new Error("Pick one of the checksum words, then Calculate.");re=ar([...n.words,ft].join(" "),r,e,t,{notes:n.notes,warnings:n.warnings})}else{let n=$n(document.getElementById("dice").value,ge);if(!n.ok)throw new Error(n.error);re=on(n,r,e,t)}else if(Ne==="hex"){let n=document.getElementById("hex").value.trim(),o=document.getElementById("bin").value.trim(),i=n?In(n):On(o);if(!i.ok)throw new Error(i.error);re=on(i,r,e,t)}else if(Ne==="seed"){let n=document.getElementById("seed").value.trim();re=/^[xtyYzZvVun][A-Za-z0-9]+$/.test(n)&&n.length>80?Po(n,e,t):ar(n,r,e,t)}else{let n=document.querySelector("input[name=kk]:checked")?.value||"wif-or-hex";re=Io(document.getElementById("key").value,e,n)}Ge=!1,hodlAccountId=null,tc()}catch(e){re=null,hodlAccountId=null,W("#error").textContent=e instanceof Error?e.message:"Could not calculate",dr.innerHTML=""}}function tc(){if(!re){dr.innerHTML="";return}if(re.kind==="single"){let t=re;dr.innerHTML=hodlSingleWalletData(t)}else{let t=re,r=t.accounts.find(o=>o.def.id===hodlAccountId)??t.accounts.find(o=>o.def.id==="bip84")??t.accounts[0];dr.innerHTML=`
      ${hodlHdWalletData(t)}
      <div class="account-tabs no-print" id="acct-tabs" role="tablist" aria-label="Script type results"></div>
      <div id="acct" role="tabpanel"></div>
    `;let n=W("#acct-tabs");t.accounts.forEach(o=>{let i=document.createElement("button");i.type="button",i.id=`account-tab-${o.def.id}`,i.className="tab account-tab"+(o.def.id===r.def.id?" active":""),i.dataset.account=o.def.id,i.textContent=o.def.label,i.setAttribute("role","tab"),i.setAttribute("aria-controls","acct"),i.setAttribute("aria-selected",String(o.def.id===r.def.id)),i.tabIndex=o.def.id===r.def.id?0:-1,i.onclick=()=>Qs(o.def.id),n.appendChild(i)}),n.onkeydown=hodlAccountTabsKeydown,Qs(r.def.id)}let e=document.getElementById("reveal");e&&(e.onchange=()=>{Ge=e.checked,tc()}),document.getElementById("save")?.addEventListener("click",()=>{if(!re)return;let t=new Blob([hodlFormatRecoverySheet(Oo(re,Ge))],{type:"text/plain"}),r=document.createElement("a");r.href=URL.createObjectURL(t),r.download="bitcoin-recovery-sheet.txt",r.click()})}

/* Correct, network-aware extended-key exports. Keep HD nodes normalized internally,
   and apply x/t/y/u/z/v version bytes only at export boundaries. */
To=To.map(definition=>definition.id==="bip86"?{...definition,slip:"x"}:definition);
cr={
  mainnet:{
    x:{pub:0x0488b21e,prv:0x0488ade4,pubName:"xpub",prvName:"xprv"},
    y:{pub:0x049d7cb2,prv:0x049d7878,pubName:"ypub",prvName:"yprv"},
    z:{pub:0x04b24746,prv:0x04b2430c,pubName:"zpub",prvName:"zprv"}
  },
  testnet:{
    x:{pub:0x043587cf,prv:0x04358394,pubName:"tpub",prvName:"tprv"},
    y:{pub:0x044a5262,prv:0x044a4e28,pubName:"upub",prvName:"uprv"},
    z:{pub:0x045f1cf6,prv:0x045f18bc,pubName:"vpub",prvName:"vprv"}
  }
};
var hodlMultisigKeyVersions=[
  {network:"mainnet",family:"y",scope:"multisig",private:!1,ver:0x0295b43f,name:"Ypub"},
  {network:"mainnet",family:"y",scope:"multisig",private:!0,ver:0x0295b005,name:"Yprv"},
  {network:"mainnet",family:"z",scope:"multisig",private:!1,ver:0x02aa7ed3,name:"Zpub"},
  {network:"mainnet",family:"z",scope:"multisig",private:!0,ver:0x02aa7a99,name:"Zprv"},
  {network:"testnet",family:"y",scope:"multisig",private:!1,ver:0x024289ef,name:"Upub"},
  {network:"testnet",family:"y",scope:"multisig",private:!0,ver:0x024285b5,name:"Uprv"},
  {network:"testnet",family:"z",scope:"multisig",private:!1,ver:0x02575483,name:"Vpub"},
  {network:"testnet",family:"z",scope:"multisig",private:!0,ver:0x02575048,name:"Vprv"}
];
So=[];
for(let [network,families] of Object.entries(cr))for(let [family,entry] of Object.entries(families)){
  So.push({network,family,scope:"singlesig",private:!1,ver:entry.pub,name:entry.pubName});
  So.push({network,family,scope:"singlesig",private:!0,ver:entry.prv,name:entry.prvName})
}
So.push(...hodlMultisigKeyVersions);
uf=function(value){
  let input=String(value??"").trim(),payload=sr.decode(input),version=lf(input),entry=So.find(candidate=>candidate.ver===version);
  if(!entry)throw new Error("Not a recognized extended key. Use xpub/xprv, tpub/tprv, ypub/yprv, zpub/zprv, upub/uprv, vpub/vprv, or a supported multisig export.");
  if(payload.length!==78)throw new Error("The extended key payload has an unexpected length.");
  let normalized=le(input,entry.private?cr.mainnet.x.prv:cr.mainnet.x.pub),node=Gt.fromExtendedKey(normalized);
  if(Boolean(node.privateKey)!==entry.private)throw new Error("The extended-key prefix does not match its key payload.");
  let depth=payload[4],childNumber=new DataView(payload.buffer,payload.byteOffset+9,4).getUint32(0,!1);
  if(node.depth!==depth)throw new Error("The extended-key depth does not match its serialized payload.");
  return{xkey:normalized,isPrivate:entry.private,network:entry.network,family:entry.family,scope:entry.scope,prefix:entry.name,version:entry.ver,node,depth,childNumber}
};
function hodlAccountExportFamily(definition){return definition.id==="bip49"?"y":definition.id==="bip84"?"z":"x"}
function hodlSerializeExtendedKey(value,network,family,isPrivate){return value?le(value,cr[network][family][isPrivate?"prv":"pub"]):null}
function hodlSerializeMultisigExtendedKey(value,network,family){
  let version=hodlMultisigKeyVersions.find(entry=>entry.network===network&&entry.family===family&&!entry.private);
  return value&&version?le(value,version.ver):null
}
function hodlBuildMultisigCosignerExports(root,network,accountIndex,masterFingerprint){
  let coinType=Rs(network);
  return[
    {accountId:"bip44",kind:"p2sh",standard:"bip45",label:"Legacy · BIP45 · No account",family:"x",accountPath:"m/45'",originPath:"45h"},
    {accountId:"bip44",kind:"p2sh",standard:"bip87",label:`Legacy · BIP87 · Account ${accountIndex}`,family:"x",accountPath:`m/87'/${coinType}'/${accountIndex}'`,originPath:`87h/${coinType}h/${accountIndex}h`},
    {accountId:"bip49",kind:"p2sh-p2wsh",label:"Nested SegWit · BIP48",family:"y",scriptIndex:1},
    {accountId:"bip84",kind:"p2wsh",label:"Native SegWit · BIP48",family:"z",scriptIndex:2}
  ].map(definition=>{
    let accountPath=definition.accountPath||`m/48'/${coinType}'/${accountIndex}'/${definition.scriptIndex}'`,originPath=definition.originPath||`48h/${coinType}h/${accountIndex}h/${definition.scriptIndex}h`;
    let node=root.derive(accountPath),publicKey=definition.family==="x"?hodlSerializeExtendedKey(node.publicExtendedKey,network,"x",!1):hodlSerializeMultisigExtendedKey(node.publicExtendedKey,network,definition.family);
    let prefix=definition.family==="x"?cr[network].x.pubName:hodlMultisigKeyVersions.find(entry=>entry.network===network&&entry.family===definition.family&&!entry.private)?.name||"extended public key";
    return{...definition,accountPath,originPath,prefix,value:`[${masterFingerprint}/${originPath}]${publicKey}`}
  })
}
function hodlStripDescriptorChecksum(descriptor){let text=String(descriptor??""),hash=text.lastIndexOf("#");return hash>=0?text.slice(0,hash):text}
function hodlWatchOnlyMultipathDescriptor(receiveDescriptor){let body=hodlStripDescriptorChecksum(receiveDescriptor);if(!body)return"";if(body.includes("/<0;1>/*"))return Le(body);if(!/\/0\/\*/.test(body))return"";return Le(body.replace(/\/0\/\*/g,"/<0;1>/*"))}
function hodlDescriptorQrSvg(payload){return Xs(payload,{ecc:"M",border:4,pixelSize:4,blackColor:"#111111",whiteColor:"#ffffff"})}
function hodlWatchOnlyDescriptorExport(receiveDescriptor,changeDescriptor){let multipath=hodlWatchOnlyMultipathDescriptor(receiveDescriptor),qr="";if(multipath){try{if(multipath.length>1000)throw new Error("Descriptor too long for a static QR.");qr=`<div class="watch-only-qr"><div class="qr qr-descriptor" aria-label="Watch-only wallet descriptor QR code">${hodlDescriptorQrSvg(multipath)}</div><p class="muted">Import this output descriptor into Sparrow or another wallet.</p></div>`}catch(error){qr=`<p class="muted">${$t(error.message||"Descriptor too long for a static QR.")} Copy the text instead, or import the receive and change descriptors separately.</p>`}}return`${ye("Watch-only wallet descriptor",multipath||"—")}${qr}<details class="wallet-advanced"><summary>Receive and change descriptors</summary>${ye("Watch-only receive descriptor",receiveDescriptor)}${ye("Watch-only change descriptor",changeDescriptor)}</details>`}
function hodlAccountResult(node,definition,network,count,options={}){
  let rawPublic=node.publicExtendedKey,rawPrivate=node.privateKey?node.privateExtendedKey:null,family=hodlAccountExportFamily(definition),primaryConfig=cr[network][family],genericConfig=cr[network].x;
  let genericPublic=hodlSerializeExtendedKey(rawPublic,network,"x",!1),genericPrivate=hodlSerializeExtendedKey(rawPrivate,network,"x",!0);
  let primaryPublic=hodlSerializeExtendedKey(rawPublic,network,family,!1),primaryPrivate=hodlSerializeExtendedKey(rawPrivate,network,family,!0);
  let origin=options.originFingerprint&&options.originPath?`[${options.originFingerprint}/${options.originPath}]`:"";
  let publicReceive=`${origin}${genericPublic}/0/*`,publicChange=`${origin}${genericPublic}/1/*`;
  let privateReceive=genericPrivate?`${origin}${genericPrivate}/0/*`:null,privateChange=genericPrivate?`${origin}${genericPrivate}/1/*`:null;
  let accountPath=options.accountPath??"Imported account key";
  return{
    def:definition,network,accountPath,accountIndex:options.accountIndex??null,originKnown:Boolean(origin),imported:Boolean(options.imported),
    masterFingerprint:options.masterFingerprint??null,parentFingerprint:options.parentFingerprint??null,nodeFingerprint:options.nodeFingerprint??null,
    primaryFamily:family,primaryPublic,primaryPrivate,primaryPublicLabel:primaryConfig.pubName,primaryPrivateLabel:primaryConfig.prvName,
    genericPublic,genericPrivate,genericPublicLabel:genericConfig.pubName,genericPrivateLabel:genericConfig.prvName,
    hasAlternateExport:family!=="x",publicExports:[{name:primaryConfig.pubName,value:primaryPublic}],privateExports:primaryPrivate?[{name:primaryConfig.prvName,value:primaryPrivate}]:[],
    xpub:genericPublic,xprv:genericPrivate,
    ypub:family==="y"?primaryPublic:null,yprv:family==="y"?primaryPrivate:null,
    zpub:family==="z"?primaryPublic:null,zprv:family==="z"?primaryPrivate:null,
    vpub:null,vprv:null,
    receiveDescriptor:Le(Ye(definition.script,publicReceive)),changeDescriptor:Le(Ye(definition.script,publicChange)),walletDescriptor:hodlWatchOnlyMultipathDescriptor(Le(Ye(definition.script,publicReceive))),
    receiveDescriptorPriv:privateReceive?Le(Ye(definition.script,privateReceive)):null,changeDescriptorPriv:privateChange?Le(Ye(definition.script,privateChange)):null,
    receive:nn(node,accountPath,definition.script,network,count,"receive"),change:nn(node,accountPath,definition.script,network,count,"change")
  }
}
mf=function(root,definition,network,count,masterFingerprint,accountIndex=0){
  let accountPath=Ao(definition,network,accountIndex),node=root.derive(accountPath),originPath=`${definition.purpose}h/${Rs(network)}h/${accountIndex}h`;
  return hodlAccountResult(node,definition,network,count,{accountPath,accountIndex,masterFingerprint,originFingerprint:masterFingerprint,originPath})
};
Hs=function(root,network,count,source,accountIndex=0){
  let addressCount=Math.min(Math.max(count,1),50),masterFingerprint=Us(root.fingerprint),accounts=To.map(definition=>mf(root,definition,network,addressCount,masterFingerprint,accountIndex));
  return{
    kind:"hd",network,mnemonic:source.mnemonic,passphraseUsed:source.passphraseUsed,entropyHex:source.entropyHex,seedHex:source.seedHex,
    rootXprv:hodlSerializeExtendedKey(root.privateKey?root.privateExtendedKey:null,network,"x",!0),rootXpub:hodlSerializeExtendedKey(root.publicExtendedKey,network,"x",!1),
    rootPrivateLabel:cr[network].x.prvName,rootPublicLabel:cr[network].x.pubName,masterFingerprint,
    multisigCosignerExports:root.privateKey?hodlBuildMultisigCosignerExports(root,network,accountIndex,masterFingerprint):[],
    imported:!1,notes:source.notes,warnings:source.warnings,accounts
  }
};
function hodlImportedScriptDefinition(parsed){
  if(parsed.family==="y")return To.find(definition=>definition.id==="bip49");
  if(parsed.family==="z")return To.find(definition=>definition.id==="bip84");
  return hodlScriptDefinition(hodlSelectedScriptType())
}
Po=function(value,network,count,accountIndex=0){
  let importedValue=String(value??"").trim(),parsed=uf(importedValue);
  if(parsed.scope!=="singlesig")throw new Error(`${parsed.prefix} is a multisig extended key. Use it in Multi Signature, not Key Derivation.`);
  if(parsed.network!==network)throw new Error(`This ${parsed.prefix} belongs to Bitcoin ${parsed.network}. Change Network to ${parsed.network} before deriving it.`);
  let node=parsed.node,notes=[parsed.isPrivate?"Imported an extended private key. Addresses and WIF keys are derived from it.":"Imported an extended public key. This is watch-only: it can derive addresses but cannot spend."];
  if(node.depth===0){
    if(!parsed.isPrivate)throw new Error("A root extended public key cannot derive the hardened BIP44/49/84/86 account paths. Import an account-level extended public key, or use the root xprv/tprv offline.");
    if(parsed.family!=="x")throw new Error("A BIP32 root private key must use the generic xprv/tprv prefix.");
    return Hs(node,network,count,{mnemonic:null,passphraseUsed:!1,entropyHex:null,seedHex:null,notes,warnings:[]},accountIndex)
  }
  if(node.depth!==3)throw new Error(`This extended key is depth ${node.depth}. Key Derivation accepts a BIP32 root private key (depth 0) or an account-level extended key (depth 3).`);
  let definition=hodlImportedScriptDefinition(parsed),addressCount=Math.min(Math.max(count,1),50),parentFingerprint=Us(node.parentFingerprint),nodeFingerprint=Us(node.fingerprint);
  let account=hodlAccountResult(node,definition,network,addressCount,{accountPath:"Imported account key",accountIndex:null,imported:!0,parentFingerprint,nodeFingerprint});
  return{
    kind:"hd",network,mnemonic:null,passphraseUsed:!1,entropyHex:null,seedHex:null,rootXprv:null,rootXpub:null,
    importedPrivateKey:parsed.isPrivate?importedValue:null,importedPublicKey:parsed.isPrivate?null:importedValue,
    importedPrivateLabel:parsed.isPrivate?parsed.prefix:null,importedPublicLabel:parsed.isPrivate?null:parsed.prefix,
    masterFingerprint:null,parentFingerprint,nodeFingerprint,imported:!0,notes,
    warnings:[...(parsed.isPrivate?[]:["Watch-only. This key contains no private key material."]),"The imported account key did not include a master fingerprint or origin path, so descriptors intentionally omit a fabricated key origin."],accounts:[account]
  }
};

function hodlAccountHasPrivate(account){
  return Boolean(account.primaryPrivate||account.receiveDescriptorPriv||account.changeDescriptorPriv||account.receive.some(row=>row.wif)||account.change.some(row=>row.wif))
}
function hodlAccountAdvancedExports(account,includePrivate=false){
  if(!account.hasAlternateExport)return"";
  let privateExport=includePrivate&&account.genericPrivate?Ee(`Generic ${account.genericPrivateLabel} for descriptor compatibility`,account.genericPrivate):"";
  let publicExport=!includePrivate&&account.genericPublic?ye(`Generic ${account.genericPublicLabel} for descriptor compatibility`,account.genericPublic):"";
  if(!privateExport&&!publicExport)return"";
  if(includePrivate)return`<div class="wallet-advanced">${privateExport}</div>`;
  return`<details class="wallet-advanced"><summary>Advanced watch-only export</summary>${publicExport}</details>`
}
function hodlRenderMultisigCosignerExport(exports,accountId){
  let items=Array.isArray(exports)?exports.filter(candidate=>candidate.accountId===accountId):[];
  return items.map(item=>ye(`Multisig co-signer ${item.prefix} · ${item.label}`,item.value)).join("")
}
function hodlAddressTable(rows,label="Addresses",includeWif=false){
  let safeLabel=$t(includeWif?`${label} with WIF private keys`:label),tableClass=includeWif?"wallet-table-private":"wallet-table-public";
  let wifHeading=includeWif?'<th scope="col">WIF</th>':"";
  let body=rows.map(row=>`<tr><th scope="row">${row.index}</th><td>${$t(hodlDisplayDerivationPath(row.path))}</td><td>${$t(row.address)}</td>${includeWif?`<td>${hodlPrivateValue(row.wif,"mono table-private-field-value")}</td>`:""}</tr>`).join("");
  return`<div class="wallet-table ${tableClass}" role="region" tabindex="0" aria-label="${safeLabel} table; scroll horizontally for more columns"><table><caption class="sr-only">${safeLabel}</caption><thead><tr><th scope="col">#</th><th scope="col">Path</th><th scope="col">Address</th>${wifHeading}</tr></thead><tbody>${body}</tbody></table></div>`
}
function Qs(id){
  if(!re||re.kind!=="hd")return;let account=re.accounts.find(candidate=>candidate.def.id===id);if(!account)return;
  hodlSetSelectedScriptType(id);hodlSyncAccountTabs(id);let firstReceive=account.receive[0],hasPrivate=hodlAccountHasPrivate(account);
  let privateSection=hasPrivate?`
    <section class="account-result-section account-private-section" aria-labelledby="account-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="account-private-heading">Private account material</h3>
        <p class="muted">These exports can spend from this account. They are shown only for a seed or extended private-key source.</p>
      </div>
      ${Ee(`Account ${account.primaryPrivateLabel}`,account.primaryPrivate)}
      ${Ee("Spending receive descriptor",account.receiveDescriptorPriv)}
      ${Ee("Spending change descriptor",account.changeDescriptorPriv)}
      ${hodlAccountAdvancedExports(account,!0)}
      <p class="account-private-warning"><strong>Keep these exports together only in secure offline backups.</strong> An account extended public key combined with any non-hardened descendant private key, including a WIF shown in the address tables below, can reconstruct that account's extended private key.</p>
    </section>`:"";
  W("#acct").innerHTML=`
    <section class="card account-result-card">
      <div class="kicker">${$t(account.def.bip)} · ${$t(re.network)}</div>
      <h2>${$t(account.def.label)}</h2>
      <p class="muted">${$t(account.def.beginner)}</p>
      ${privateSection}
      <section class="account-result-section account-watch-section" aria-labelledby="account-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-watch-heading">Watch-only wallet data</h3>
          <p class="watch-only-note"><strong>Cannot spend:</strong> these exports can monitor every address and reveal this account's transaction history and balance. Treat them as privacy-sensitive.</p>
        </div>
        ${ye(`Account ${account.primaryPublicLabel}`,account.primaryPublic)}
        ${hodlRenderMultisigCosignerExport(re.multisigCosignerExports,account.def.id)}
        ${hodlWatchOnlyDescriptorExport(account.receiveDescriptor,account.changeDescriptor)}
        ${hodlAccountAdvancedExports(account,!1)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="account-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="account-address-heading">Addresses</h3>
          <p class="muted">Verify the first receive address on another trusted wallet or signing device before accepting bitcoin.</p>
        </div>
        ${firstReceive?`<div class="account-address-lead"><h4 class="wallet-data-subtitle">Receive address #0</h4><div class="qr" aria-label="Receive address 0 QR code">${an(firstReceive.address)}</div><p class="mono">${$t(firstReceive.address)}</p><p class="muted mono">${$t(hodlDisplayDerivationPath(firstReceive.path))}</p></div>`:""}
        <h4 class="wallet-data-subtitle">Receive</h4>
        ${hodlAddressTable(account.receive,"Receive addresses",hasPrivate)}
        <h4 class="wallet-data-subtitle">Change</h4>
        ${hodlAddressTable(account.change,"Change addresses",hasPrivate)}
      </section>
    </section>`
}
function ye(label,value){return`<p><span class="muted">${$t(label)}</span><br><span class="mono">${$t(value??"\u2014")}</span></p>`}
function hodlPrivateValue(value,className="secret private-field-value"){let mask="************",text=String(value??"\u2014");if(Ge)return`<span class="${className}">${$t(text)}</span>`;let bullets="\u2022".repeat(Math.max(Array.from(text).length,mask.length));return`<span class="${className} secret-placeholder"><span class="secret-placeholder-mask" aria-hidden="true">${bullets}</span><span class="secret-placeholder-message" aria-hidden="true">${mask}</span><span class="secret-placeholder-label">Private value hidden</span></span>`}
function Ee(label,value){return`<p class="private-field"><span class="muted">${$t(label)}</span>${hodlPrivateValue(value)}</p>`}
function hodlDisplayDerivationPath(value){return String(value??"").replace(/(^|\/)(\d+)'(?=\/|$)/g,"$1$2h")}
function Js(rows){return hodlAddressTable(rows,"Addresses")}
function $t(value){let entities={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};return Array.from(String(value??""),character=>entities[character]??character).join("")}

function hodlPrivateDataControls(descriptionId,scope="wallet"){
  let privateSheet=Ge,downloadLabel=privateSheet?"Save unencrypted private sheet":"Save watch-only sheet";
  let disclosure=privateSheet
    ?scope==="wallet"
      ?"The downloaded plain-text file is unencrypted and includes all available root and account private recovery material across every script type."
      :"The downloaded plain-text file is unencrypted and includes every private key shown in this section."
    :"The downloaded sheet omits all private recovery material.";
  return`<div class="wallet-data-actions no-print">
    <label class="reveal-private-toggle">
      <input type="checkbox" id="reveal" ${Ge?"checked":""} aria-describedby="${descriptionId} recovery-sheet-disclosure" />
      <span>Show private recovery material <span class="reveal-private-toggle-note">(air-gap only)</span></span>
    </label>
    <button class="btn secondary save-recovery-sheet" id="save" type="button" aria-describedby="recovery-sheet-disclosure">${downloadLabel}</button>
    <p class="recovery-download-disclosure" id="recovery-sheet-disclosure"><strong>${privateSheet?"Private export:":"Watch-only export:"}</strong> ${disclosure}</p>
  </div>`
}
function hodlSaveRecoveryControl(){return`<div class="wallet-data-actions no-print"><button class="btn secondary save-recovery-sheet" id="save" type="button">Save watch-only sheet</button></div>`}
function hodlWalletMessages(wallet,idPrefix){
  let warnings=[...(wallet.warnings||[])].filter(message=>!wallet.passphraseUsed||!/\bpassphrase\b/i.test(message)),notes=[...(wallet.notes||[])];
  if(wallet.passphraseUsed)warnings.unshift("A BIP39 passphrase is in use. It creates a different wallet, is not printed in the recovery sheet, and must be preserved separately to recover this wallet.");
  if(!warnings.length&&!notes.length)return"";
  let items=[...warnings.map(message=>`<li class="is-warning">${$t(message)}</li>`),...notes.map(message=>`<li>${$t(message)}</li>`)].join("");
  return`<section class="wallet-result-messages" aria-labelledby="${idPrefix}-safety-heading"><h3 id="${idPrefix}-safety-heading">Safety notes</h3><ul>${items}</ul></section>`
}
function hodlSingleWalletData(wallet){
  let miniKey=wallet.minikey?Ee("Mini private key",wallet.minikey):"";
  return`<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">Single-key wallet data</div>
      <h2 tabindex="-1">Key recovery details</h2>
      <p class="muted">Review the private key and addresses derived from this input. Sensitive recovery material is grouped first; public wallet data appears below.</p>
      ${hodlWalletMessages(wallet,"single")}
    </div>
    <section class="wallet-data-section wallet-private-section" aria-labelledby="single-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-private-heading">Private key material</h3>
        <p class="muted" id="single-private-description">These values can spend the bitcoin held by the addresses below. Reveal them only while this file is running offline on an air-gapped computer.</p>
      </div>
      ${hodlPrivateDataControls("single-private-description","single")}
      <div class="wallet-data-fields">
        ${Ee("WIF compressed",wallet.wifCompressed)}
        ${Ee("WIF uncompressed",wallet.wifUncompressed)}
        ${Ee("Hex private key",wallet.privHex)}
        ${miniKey}
      </div>
    </section>
    <section class="wallet-data-section wallet-public-section" aria-labelledby="single-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="single-public-heading">Public keys &amp; addresses</h3>
        <p class="muted">Use these values for verification or watch-only monitoring. They do not reveal the private key.</p>
      </div>
      <div class="wallet-data-fields">
        ${ye("Compressed public key",wallet.pubkeyCompressed)}
        ${ye("Uncompressed public key",wallet.pubkeyUncompressed)}
        <h4 class="wallet-data-subtitle">Addresses</h4>
        ${ye("Legacy uncompressed",wallet.p2pkhUncompressed)}
        ${ye("Legacy compressed",wallet.p2pkhCompressed)}
        ${ye("Nested SegWit",wallet.p2shP2wpkh)}
        ${ye("Native SegWit",wallet.p2wpkh)}
        ${ye("Taproot",wallet.p2tr)}
        <h4 class="wallet-data-subtitle">Native SegWit QR code</h4>
        <div class="qr" aria-label="Native SegWit address QR code">${an(wallet.p2wpkh)}</div>
      </div>
    </section>
  </section>`
}
function hodlHdWalletData(wallet){
  let privateFields=[];
  if(wallet.mnemonic)privateFields.push(hodlSeedPhraseField(`Your seed phrase \u00b7 ${wallet.mnemonic.trim().split(/\s+/).length} words`,wallet.mnemonic),hodlSeedQrExport(wallet.mnemonic,{passphraseUsed:wallet.passphraseUsed,entropyHex:wallet.entropyHex}));
  if(wallet.entropyHex)privateFields.push(Ee("BIP39 entropy hex",wallet.entropyHex));
  if(wallet.seedHex)privateFields.push(Ee("Master seed hex",wallet.seedHex));
  if(wallet.rootXprv)privateFields.push(Ee(`Root ${wallet.rootPrivateLabel||cr[wallet.network].x.prvName}`,wallet.rootXprv));
  if(wallet.importedPrivateKey)privateFields.push(Ee(`Imported ${wallet.importedPrivateLabel||"extended private key"}`,wallet.importedPrivateKey));
  let hasAccountPrivate=wallet.accounts.some(hodlAccountHasPrivate),hasPrivate=privateFields.length>0||hasAccountPrivate;
  let privateContent=privateFields.length?privateFields.join(""):`<p class="muted">Private account material is available in the selected script panel below; no BIP32 root private key was supplied.</p>`;
  let intro=wallet.mnemonic?"Review the root material derived from this seed. Private recovery data is grouped first; watch-only data appears below.":"Review the material available from this imported extended key. Private data, when present, is grouped first; watch-only data appears below.";
  let source=wallet.mnemonic?"":`<p><span class="muted">Source</span><br><span>Imported extended ${hasPrivate?"private":"public"} key; no seed phrase was entered.</span></p>`;
  let privateSection=hasPrivate?`<section class="wallet-data-section wallet-private-section" aria-labelledby="wallet-private-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-private-heading">Private recovery material</h3>
        <p class="muted" id="wallet-private-description">These values can recreate or spend from the wallet. Reveal them only while this file is running offline on an air-gapped computer.</p>
      </div>
      ${hodlPrivateDataControls("wallet-private-description")}
      <div class="wallet-data-fields">${privateContent}</div>
    </section>`:"";
  let fingerprint=wallet.masterFingerprint?ye("Master fingerprint",wallet.masterFingerprint):"";
  let parentFingerprint=!wallet.masterFingerprint&&wallet.parentFingerprint?ye("Encoded parent fingerprint (not a master fingerprint)",wallet.parentFingerprint):"";
  let nodeFingerprint=!wallet.masterFingerprint&&wallet.nodeFingerprint?ye("Imported key fingerprint (not a master fingerprint)",wallet.nodeFingerprint):"";
  let rootPublic=wallet.rootXpub?ye(`Root ${wallet.rootPublicLabel||cr[wallet.network].x.pubName}`,wallet.rootXpub):"";
  let importedPublic=wallet.importedPublicKey?ye(`Imported ${wallet.importedPublicLabel||"extended public key"}`,wallet.importedPublicKey):"";
  return`<section class="card wallet-data-card">
    <div class="wallet-data-intro">
      <div class="kicker">Wallet data</div>
      <h2 tabindex="-1">Wallet recovery details</h2>
      <p class="muted">${intro}</p>
      ${hodlWalletMessages(wallet,"wallet")}
    </div>
    ${privateSection}
    <section class="wallet-data-section wallet-public-section" aria-labelledby="wallet-public-heading">
      <div class="wallet-data-section-head">
        <h3 id="wallet-public-heading">Watch-only wallet data</h3>
        <p class="muted">These values identify the wallet or enable watch-only use, but do not authorize spending. Treat them as privacy-sensitive because extended public keys and descriptors can reveal wallet addresses, balances, and transaction history.</p>
      </div>
      ${hasPrivate?"":hodlSaveRecoveryControl()}
      <div class="wallet-data-fields">
        ${fingerprint}
        ${parentFingerprint}
        ${nodeFingerprint}
        ${rootPublic}
        ${importedPublic}
        ${source}
      </div>
    </section>
  </section>`
}

function hodlDownloadRecoverySheet(){
  if(!re)return;
  let blob=new Blob([hodlFormatRecoverySheet(Oo(re,Ge))],{type:"text/plain"}),url=URL.createObjectURL(blob),link=document.createElement("a");
  link.href=url;link.download="bitcoin-recovery-sheet.txt";link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}
function hodlBindWalletResultActions(){
  let reveal=document.getElementById("reveal");
  if(reveal)reveal.onchange=()=>{Ge=reveal.checked;tc();requestAnimationFrame(()=>document.getElementById("reveal")?.focus({preventScroll:true}))};
  let save=document.getElementById("save");
  if(save){let clean=save.cloneNode(!0);save.replaceWith(clean);clean.addEventListener("click",hodlDownloadRecoverySheet)}
}
function hodlFocusWalletResult(){
  requestAnimationFrame(()=>dr.querySelector(".wallet-data-intro h2, .account-result-card > h2")?.focus({preventScroll:!1}))
}
var hodlRenderWalletBase=tc;
tc=function(){hodlRenderWalletBase();hodlBindWalletResultActions()};

function hodlSheetWarnings(lines,wallet){
  for(let note of wallet.notes||[])lines.push(`Note: ${note}`);
  for(let warning of wallet.warnings||[])lines.push(`Warning: ${warning}`)
}
function hodlSheetAddressRows(lines,label,rows){
  lines.push(label.toUpperCase());
  for(let row of rows)lines.push(`  ${row.index}  ${hodlDisplayDerivationPath(row.path)}  ${row.address}`)
}
function hodlSheetWifRows(lines,label,rows){
  let privateRows=rows.filter(row=>row.wif);if(!privateRows.length)return;
  lines.push(label.toUpperCase());
  for(let row of privateRows)lines.push(`  ${row.index}  ${hodlDisplayDerivationPath(row.path)}  ${row.wif}`)
}
Oo=function(wallet,revealPrivate){
  let lines=["ENTROPYLAB \u2014 RECOVERY SHEET","This file was computed locally. The calculator never generated wallet entropy.",""];
  lines.push(`Network: ${wallet.network}`);if(wallet.passphraseUsed)lines.push("Passphrase: YES (not printed)");hodlSheetWarnings(lines,wallet);lines.push("");
  if(wallet.kind==="single"){
    if(revealPrivate){
      lines.push("PRIVATE RECOVERY MATERIAL",`WIF compressed:   ${wallet.wifCompressed??""}`,`WIF uncompressed: ${wallet.wifUncompressed??""}`,`Hex private key:  ${wallet.privHex??""}`);if(wallet.minikey)lines.push(`Mini key: ${wallet.minikey}`)
    }else lines.push("PRIVATE RECOVERY MATERIAL OMITTED","Private values were not saved because Show private recovery material was off.");
    lines.push("","PUBLIC KEYS AND ADDRESSES",`Compressed public key:   ${wallet.pubkeyCompressed}`,`Uncompressed public key: ${wallet.pubkeyUncompressed}`,`Legacy uncompressed: ${wallet.p2pkhUncompressed}`,`Legacy compressed:   ${wallet.p2pkhCompressed}`,`Nested SegWit:       ${wallet.p2shP2wpkh}`,`Native SegWit:       ${wallet.p2wpkh}`,`Taproot:             ${wallet.p2tr}`);
    return lines.join("\n")
  }
  let hasPrivate=Boolean(wallet.mnemonic||wallet.entropyHex||wallet.seedHex||wallet.rootXprv||wallet.importedPrivateKey||wallet.accounts.some(hodlAccountHasPrivate));
  if(hasPrivate&&revealPrivate){
    lines.push("PRIVATE RECOVERY MATERIAL");
    if(wallet.mnemonic){lines.push("","YOUR SEED PHRASE",wallet.mnemonic);let seedQrDigits=hodlSeedQrDigits(wallet.mnemonic);if(seedQrDigits)lines.push("","SEEDQR DIGITS",seedQrDigits)}
    if(wallet.entropyHex)lines.push("","BIP39 ENTROPY HEX",wallet.entropyHex);
    if(wallet.seedHex)lines.push("","MASTER SEED HEX (BIP39 PBKDF2, 512 bits)",wallet.seedHex);
    if(wallet.rootXprv)lines.push("",`BIP32 ROOT ${(wallet.rootPrivateLabel||cr[wallet.network].x.prvName).toUpperCase()}`,wallet.rootXprv);
    if(wallet.importedPrivateKey)lines.push("",`IMPORTED ${(wallet.importedPrivateLabel||"EXTENDED PRIVATE KEY").toUpperCase()}`,wallet.importedPrivateKey);
    for(let account of wallet.accounts){
      if(!hodlAccountHasPrivate(account))continue;
      lines.push("",`-- ${account.def.label} (${account.def.bip}) PRIVATE ACCOUNT MATERIAL --`);
      if(account.primaryPrivate)lines.push(`${account.primaryPrivateLabel}: ${account.primaryPrivate}`);
      if(account.hasAlternateExport&&account.genericPrivate)lines.push(`Advanced ${account.genericPrivateLabel} descriptor export: ${account.genericPrivate}`);
      if(account.receiveDescriptorPriv)lines.push(`Spending receive descriptor: ${account.receiveDescriptorPriv}`);
      if(account.changeDescriptorPriv)lines.push(`Spending change descriptor:  ${account.changeDescriptorPriv}`);
      lines.push("Warning: An account extended public key plus a non-hardened descendant private key can reconstruct the account extended private key.");
      hodlSheetWifRows(lines,"Receive-address private keys (WIF)",account.receive);
      hodlSheetWifRows(lines,"Change-address private keys (WIF)",account.change)
    }
  }else if(hasPrivate){
    lines.push("PRIVATE RECOVERY MATERIAL OMITTED","Private values were not saved because Show private recovery material was off.")
  }else{
    lines.push("NO PRIVATE RECOVERY MATERIAL","This source was watch-only; no private keys were available to save.")
  }
  lines.push("","WATCH-ONLY WALLET DATA","Privacy note: Extended public keys and descriptors cannot spend, but can reveal wallet history and balances.");
  if(wallet.masterFingerprint)lines.push(`Master fingerprint: ${wallet.masterFingerprint}`);
  if(wallet.parentFingerprint&&!wallet.masterFingerprint)lines.push(`Encoded parent fingerprint (not a master fingerprint): ${wallet.parentFingerprint}`);
  if(wallet.nodeFingerprint&&!wallet.masterFingerprint)lines.push(`Imported key fingerprint (not a master fingerprint): ${wallet.nodeFingerprint}`);
  if(wallet.rootXpub)lines.push(`BIP32 root ${(wallet.rootPublicLabel||cr[wallet.network].x.pubName).toUpperCase()}: ${wallet.rootXpub}`);
  if(wallet.multisigCosignerExports?.length){
    lines.push("","MULTISIG CO-SIGNER EXPORTS","Paste one complete value into a co-signer input. Legacy offers BIP45 without accounts and BIP87 with standardized accounts; use the same standard and account policy for every co-signer.");
    for(let item of wallet.multisigCosignerExports)lines.push(`${item.label} (${item.prefix}): ${item.value}`)
  }
  if(wallet.importedPublicKey)lines.push(`Imported ${(wallet.importedPublicLabel||"extended public key").toUpperCase()}: ${wallet.importedPublicKey}`);
  for(let account of wallet.accounts){
    lines.push("",`=== ${account.def.label} (${account.def.bip}) ===`,account.def.beginner,`Network: ${wallet.network}`,`Account: ${account.imported?"Imported account key":account.accountIndex??0}`,`Account path: ${hodlDisplayDerivationPath(account.accountPath)}`);
    if(account.masterFingerprint||wallet.masterFingerprint)lines.push(`Master fingerprint: ${account.masterFingerprint||wallet.masterFingerprint}`);
    else if(account.parentFingerprint)lines.push(`Encoded parent fingerprint (not a master fingerprint): ${account.parentFingerprint}`);
    if(!account.masterFingerprint&&!wallet.masterFingerprint&&account.nodeFingerprint)lines.push(`Imported key fingerprint (not a master fingerprint): ${account.nodeFingerprint}`);
    lines.push("WATCH-ONLY EXPORTS",`${account.primaryPublicLabel}: ${account.primaryPublic}`,...(account.walletDescriptor?[`Watch-only wallet descriptor: ${account.walletDescriptor}`]:[]),`Watch-only receive descriptor: ${account.receiveDescriptor}`,`Watch-only change descriptor:  ${account.changeDescriptor}`);
    if(account.hasAlternateExport)lines.push(`Advanced ${account.genericPublicLabel} descriptor export: ${account.genericPublic}`);
    lines.push("ADDRESSES");hodlSheetAddressRows(lines,"Receive",account.receive);hodlSheetAddressRows(lines,"Change",account.change)
  }
  return lines.join("\n")
};

var hodlMaxAccount=2147483647;
function hodlScriptDefinition(id){return To.find(definition=>definition.id===id)||To.find(definition=>definition.id==="bip84")||To[0]}
function hodlSelectedScriptType(){
  let value=document.getElementById("script-type")?.value||hodlAccountId||"bip84";
  return hodlScriptDefinition(value).id
}
function hodlSetSelectedScriptType(value){
  let id=hodlScriptDefinition(value).id;hodlAccountId=id;
  hodlSyncSelect(document.getElementById("script-type"),id);
  let state=hodlKeys[hodlActiveKey];if(state){state.accountId=id;state.fields.script=id}
  hodlUpdateDerivationPathPreview();return id
}
function hodlSyncAccountTabs(id){
  let box=document.getElementById("acct-tabs"),panel=document.getElementById("acct");if(!box)return;
  let buttons=[...box.querySelectorAll("[data-account]")],activeIndex=-1;
  buttons.forEach((button,index)=>{let active=button.dataset.account===id;button.classList.toggle("active",active);button.setAttribute("aria-selected",String(active));button.tabIndex=active?0:-1;if(active)activeIndex=index});
  let active=activeIndex>=0?buttons[activeIndex]:null;if(panel&&active)panel.setAttribute("aria-labelledby",active.id);
  if(activeIndex>=0)hodlRevealTab(box,activeIndex)
}
function hodlAccountTabsKeydown(event){
  let current=event.target instanceof Element?event.target.closest(".account-tab"):null,box=event.currentTarget;if(!current||!box)return;
  let buttons=[...box.querySelectorAll(".account-tab")],index=buttons.indexOf(current),next=null;
  if(event.key==="ArrowRight")next=(index+1)%buttons.length;else if(event.key==="ArrowLeft")next=(index-1+buttons.length)%buttons.length;else if(event.key==="Home")next=0;else if(event.key==="End")next=buttons.length-1;
  if(next===null)return;event.preventDefault();buttons[next].click();buttons[next].focus()
}
function hodlReadAccount(){
  let input=document.getElementById("account"),raw=String(input?.value??"").trim(),message="Account must be a whole number from 0 to 2,147,483,647.";
  let invalid=()=>{if(input){input.classList.add("bad");input.setAttribute("aria-invalid","true")}throw new Error(message)};
  if(!/^\d+$/.test(raw))invalid();let value=Number(raw);if(!Number.isSafeInteger(value)||value<0||value>hodlMaxAccount)invalid();
  if(input){input.classList.remove("bad");input.setAttribute("aria-invalid","false")}return value
}
function hodlImportedExtendedKeyDepth(){
  if(Ne!=="seed")return null;let value=document.getElementById("seed")?.value.trim()||"";if(!hodlLooksExtendedKey(value))return null;
  try{let normalized=uf(value);return Gt.fromExtendedKey(normalized.xkey).depth}catch{return null}
}
function hodlUpdateKeyModeControls(){
  let singleKey=Ne==="key",settings=document.getElementById("key-settings");
  ["passphrase-field","master-fingerprint-preview","script-type-field","account-address-settings","derivation-path-preview"].forEach(id=>{
    let element=document.getElementById(id);if(element)element.hidden=singleKey
  });
  settings?.classList.toggle("single-key-mode",singleKey)
}
function hodlUpdateDerivationPathPreview(){
  let panel=document.getElementById("derivation-path-preview"),list=panel?.querySelector(".derivation-path-list"),context=document.getElementById("derivation-path-context"),message=document.getElementById("derivation-path-error"),accountInput=document.getElementById("account");
  if(!panel||!list||!context||!message)return;
  hodlUpdateKeyModeControls();
  let setPath=(name,value)=>{let node=panel.querySelector(`[data-path="${name}"]`);if(node)node.textContent=value};
  let showMessage=(text,isError=false)=>{list.hidden=!0;message.hidden=!1;message.textContent=text;message.classList.toggle("is-note",!isError);panel.classList.toggle("is-invalid",isError)};
  let clearMessage=()=>{list.hidden=!1;message.hidden=!0;message.textContent="";message.classList.remove("is-note");panel.classList.remove("is-invalid")};
  let definition=hodlScriptDefinition(hodlSelectedScriptType());
  if(Ne==="key"){
    accountInput?.classList.remove("bad");accountInput?.setAttribute("aria-invalid","false");context.textContent="";message.textContent="";panel.classList.remove("is-invalid");return
  }
  let account;try{account=hodlReadAccount()}catch(error){context.textContent="Invalid account";showMessage(error.message||"Invalid account.",true);return}
  let network=hodlSelectedNetwork(document.getElementById("network")),count=Math.min(Math.max(Number(document.getElementById("count")?.value)||5,1),50),last=count-1;
  context.textContent=`${definition.label} · ${definition.bip}`;clearMessage();
  if((hodlImportedExtendedKeyDepth()??0)>0){
    setPath("account","Imported key base");setPath("receive",`imported-key/0/0 → imported-key/0/${last}`);setPath("change",`imported-key/1/0 → imported-key/1/${last}`);
    message.hidden=!1;message.classList.add("is-note");message.textContent=`This non-root extended key is reused directly. Account ${account} cannot select a hardened sibling.`;return
  }
  let base=`m/${definition.purpose}h/${network==="mainnet"?0:1}h/${account}h`;
  setPath("account",base);setPath("receive",`${base}/0/0 → ${base}/0/${last}`);setPath("change",`${base}/1/0 → ${base}/1/${last}`)
}
function hodlInitDerivationControls(){
  let panel=document.getElementById("calc-card");if(!panel)return;
  panel.addEventListener("input",event=>{
    let target=event.target;if(!(target instanceof Element))return;
    if(target.id==="account"){
      let state=hodlKeys[hodlActiveKey];if(state)state.fields.account=target.value;
      hodlInvalidateLiveKeyResult();let error=document.getElementById("error");if(error)error.textContent="";hodlUpdateDerivationPathPreview();return
    }
    if(target.id==="seed")hodlUpdateDerivationPathPreview()
  });
  panel.addEventListener("change",event=>{
    let target=event.target;if(!(target instanceof Element))return;
    if(target.id==="script-type"){
      let id=hodlSetSelectedScriptType(target.value);
      if(re?.kind==="hd"){if(re.accounts.some(account=>account.def.id===id))Qs(id);else hodlInvalidateLiveKeyResult()}
      let seed=document.getElementById("seed");if(seed)seed.dispatchEvent(new Event("input"));return
    }
    if(target.id==="network"||target.id==="count"){
      let state=hodlKeys[hodlActiveKey];if(state)state.fields[target.id]=target.value;
      hodlInvalidateLiveKeyResult();let error=document.getElementById("error");if(error)error.textContent="";hodlUpdateDerivationPathPreview();if(target.id==="network"){let seed=document.getElementById("seed"),key=document.getElementById("key");if(seed)seed.dispatchEvent(new Event("input"));if(key)key.dispatchEvent(new Event("input"))}
    }
  });
  hodlUpdateDerivationPathPreview()
}

function hodlSeedPhraseTokens(value,mask=false){
  return String(value??"").trim().split(/\s+/).filter(Boolean).map(word=>`<span class="seed-phrase-word">${mask?"\u2022".repeat(Array.from(word).length):$t(word)}</span>`).join(" ")
}
function hodlSeedPhraseField(label,value){
  let text=String(value??"\u2014");
  if(Ge)return`<p class="private-field seed-phrase-field"><span class="muted">${$t(label)}</span><span class="secret private-field-value seed-phrase-value">${hodlSeedPhraseTokens(text)}</span></p>`;
  return`<p class="private-field seed-phrase-field"><span class="muted">${$t(label)}</span><span class="secret private-field-value secret-placeholder seed-phrase-value"><span class="secret-placeholder-mask" aria-hidden="true">${hodlSeedPhraseTokens(text,true)}</span><span class="secret-placeholder-message" aria-hidden="true">************</span><span class="secret-placeholder-label">Private value hidden</span></span></p>`
}
function hodlSeedQrDigits(mnemonic){
  let words=String(mnemonic??"").trim().split(/\s+/).filter(Boolean);
  if(words.length!==12&&words.length!==24)return"";
  let digits="";
  for(let word of words){
    let index=Ae.indexOf(word);
    if(index<0)return"";
    digits+=String(index).padStart(4,"0");
  }
  return digits
}
function hodlCompactSeedQrBytes(entropyHex){
  let hex=String(entropyHex??"").replace(/\s/g,"").toLowerCase();
  if(hex.length!==32&&hex.length!==64)return null;
  return Array.from(M.decode(hex))
}
function hodlSeedQrExport(mnemonic,options={}){
  let words=String(mnemonic??"").trim().split(/\s+/).filter(Boolean);
  if(!words.length||!Ge)return"";
  if(words.length!==12&&words.length!==24)return`<details class="wallet-advanced"><summary>SeedQR</summary><p class="muted">SeedQR is defined for 12 and 24 word phrases. Type this ${words.length}-word seed on the signer.</p></details>`;
  let digits=hodlSeedQrDigits(mnemonic);
  if(!digits)return"";
  let passNote=options.passphraseUsed?" This QR is the seed only. Enter the passphrase on the signer after scanning.":"";
  let compact="";
  try{
    let bytes=hodlCompactSeedQrBytes(options.entropyHex);
    if(bytes)compact=`<div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="CompactSeedQR">${Xs(bytes,{ecc:"L",border:4,pixelSize:4,blackColor:"#111111",whiteColor:"#ffffff"})}</div><p class="muted">CompactSeedQR. Same seed, smaller binary code.</p><p class="muted">Compatible with: SeedSigner, Krux, Jade, Passport.</p></div>`;
  }catch{}
  return`<details class="wallet-advanced"><summary>SeedQR</summary><p class="muted">Scan into a camera signer. This is the seed.${passNote}</p><div class="seed-qr-pair"><div class="watch-only-qr seed-qr"><div class="qr qr-seed" aria-label="SeedQR">${Xs(digits,{ecc:"L",border:4,pixelSize:4,blackColor:"#111111",whiteColor:"#ffffff"})}</div><p class="muted">SeedQR. Numeric.</p><p class="muted">Compatible with: SeedSigner, Krux, Jade, Passport, Coldcard Q.</p><p class="muted mono">${$t(digits)}</p></div>${compact}</div></details>`
}

var hodlSeedLengths=Object.freeze({
  12:Object.freeze({words:12,bits:128,bytes:16,hexChars:32,hashRolls:50,partialWords:11,candidates:128}),
  18:Object.freeze({words:18,bits:192,bytes:24,hexChars:48,hashRolls:75,partialWords:17,candidates:32}),
  24:Object.freeze({words:24,bits:256,bytes:32,hexChars:64,hashRolls:99,partialWords:23,candidates:8})
});
var hodlBip39WordSet=new Set(Ae);
function hodlSeedConfig(words=Pt){return hodlSeedLengths[Number(words)]||hodlSeedLengths[24]}
function hodlLooksExtendedKey(value){return/^[xtyzuvYZUV][A-Za-z0-9]+$/.test(value.trim())&&value.trim().length>80}
function hodlSinglesigImportStatus(value,network){
  try{
    let parsed=uf(value),depth=parsed.node.depth;
    if(parsed.scope!=="singlesig")return{ok:!1,message:`${parsed.prefix} is a multisig export · use Multi Signature`};
    if(parsed.network!==network)return{ok:!1,message:`${parsed.prefix} is for ${parsed.network} · change Network to ${parsed.network}`};
    if(depth===0&&!parsed.isPrivate)return{ok:!1,message:"Root extended public keys cannot derive hardened account paths · import an account-level public key"};
    if(depth===0&&parsed.family!=="x")return{ok:!1,message:"A root private key must use an xprv/tprv prefix"};
    if(depth!==0&&depth!==3)return{ok:!1,message:`Depth ${depth} extended key · use a root private key or depth-3 account key`};
    let definition=depth===3?hodlImportedScriptDefinition(parsed):null,detail=definition?` · ${definition.label} ${definition.bip}`:"";
    return{ok:!0,message:`${parsed.prefix} ${parsed.isPrivate?"private":"watch-only"} key detected · ${network}${detail} · ready to derive`}
  }catch(error){return{ok:!1,message:error.message||"Invalid extended key"}}
}
function hodlUsableSinglesigImport(value,network){
  return hodlSinglesigImportStatus(value,network).ok
}
function hodlDPlusD16Value(face,numberedD16=hodlDPlusNumberedD16){
  let normalized=String(face??"").toUpperCase();if(numberedD16&&normalized==="G")return 0;
  let valid=numberedD16?/^[1-9A-F]$/.test(normalized):/^[0-9A-F]$/.test(normalized);if(!valid)return null;
  return Number.parseInt(normalized,16)
}
function hodlTranslateDPlusD16Notation(value,targetWords=Pt){
  let rolledCharacters=hodlSeedConfig(targetWords).partialWords*3,ordinal=0,translated="";
  for(let character of String(value??"")){
    if(/\s|,|;|\|/.test(character)){translated+=character;continue}
    let normalized=character.toUpperCase();if(!/^[0-9A-G]$/.test(normalized)){translated+=character;continue}let isD16=ordinal<rolledCharacters&&ordinal%3!==0;
    translated+=isD16&&/[0G]/.test(normalized)?normalized==="0"?"G":"0":character;ordinal+=1
  }
  return translated
}
function hodlDPlusRolls(value,targetWords=Pt,numberedD16=hodlDPlusNumberedD16){
  let config=hodlSeedConfig(targetWords),rolledTarget=config.partialWords,rolledCharacterTarget=rolledTarget*3,entries=[],invalidRanges=[],rejectedD8=0,rejectedD16=0,acceptedCharacters=[];
  for(let index=0;index<value.length;){
    let character=String.fromCodePoint(value.codePointAt(index)),end=index+character.length,normalized=character.toUpperCase();
    if(/\s|,|;|\|/.test(character)){index=end;continue}
    entries.push({face:normalized,start:index,end});index=end
  }
  let rolledEntries=entries.slice(0,rolledCharacterTarget),wordSlots=Array(rolledTarget).fill(""),groups=[],invalidRequiredCount=0,firstInvalid=null,bits=0;
  for(let groupIndex=0;groupIndex<rolledTarget;groupIndex++){
    let tokens=rolledEntries.slice(groupIndex*3,groupIndex*3+3);if(!tokens.length)break;
    let validity=tokens.map((token,position)=>position===0?/^[1-8]$/.test(token.face):hodlDPlusD16Value(token.face,numberedD16)!==null);
    tokens.forEach((token,position)=>{
      if(validity[position]){acceptedCharacters.push(token.face);bits+=[3,4,4][position];return}
      invalidRanges.push([token.start,token.end]);invalidRequiredCount+=1;if(position===0)rejectedD8+=1;else rejectedD16+=1;
      if(!firstInvalid)firstInvalid={groupIndex,position,face:token.face,start:token.start,end:token.end,final:!1}
    });
    let complete=tokens.length===3,valid=complete&&validity.every(Boolean),word="";
    if(valid){let wordIndex=(Number(tokens[0].face)-1)*256+hodlDPlusD16Value(tokens[1].face,numberedD16)*16+hodlDPlusD16Value(tokens[2].face,numberedD16);word=Ae[wordIndex];wordSlots[groupIndex]=word}
    groups.push({groupIndex,faces:tokens.map(token=>token.face),complete,valid,word,validity})
  }
  let completedGroups=Math.min(rolledTarget,Math.floor(rolledEntries.length/3)),validWordCount=wordSlots.filter(Boolean).length,allRolledComplete=rolledEntries.length===rolledCharacterTarget,rolledInvalidCount=invalidRequiredCount,allRolledValid=allRolledComplete&&rolledInvalidCount===0&&validWordCount===rolledTarget;
  let finalEntry=config.words===24?entries[rolledCharacterTarget]||null:null,finalRoll="";
  if(finalEntry){
    if(/^[1-8]$/.test(finalEntry.face)){finalRoll=finalEntry.face;acceptedCharacters.push(finalEntry.face);bits+=3}
    else{invalidRanges.push([finalEntry.start,finalEntry.end]);invalidRequiredCount+=1;rejectedD8+=1;if(!firstInvalid)firstInvalid={groupIndex:rolledTarget,position:0,face:finalEntry.face,start:finalEntry.start,end:finalEntry.end,final:!0}}
  }
  let expectedCharacters=rolledCharacterTarget+(config.words===24?1:0),extraEntries=entries.slice(expectedCharacters),extraAfter=extraEntries.length;extraEntries.forEach(token=>invalidRanges.push([token.start,token.end]));
  let finalOptions=allRolledValid?hodlTargetLastWords(wordSlots.join(" "),config.words):null,candidates=finalOptions&&!finalOptions.error?finalOptions.candidates:[],finalWord=finalRoll?candidates[Number(finalRoll)-1]||"":"";
  let currentPosition=rolledEntries.length<rolledCharacterTarget?rolledEntries.length%3:null,activeGroupIndex=rolledEntries.length<rolledCharacterTarget?Math.floor(rolledEntries.length/3):rolledTarget-1,waiting;
  if(!allRolledComplete)waiting=currentPosition===0?"d8":currentPosition===1?"d16-first":"d16-second";
  else if(!allRolledValid)waiting="correction";
  else if(config.words!==24)waiting="last-word";
  else if(!finalEntry)waiting="checksum-d8";
  else waiting=finalRoll?"complete":"correction";
  let partialLength=rolledEntries.length%3,group=partialLength?rolledEntries.slice(-partialLength).map(token=>token.face):[],words=wordSlots.filter(Boolean),notes=[`D++: ${completedGroups} of ${rolledTarget} positional D8 + D16 + D16 groups entered; ${validWordCount} valid (${rolledEntries.length} of ${rolledCharacterTarget} required faces).`],warnings=[];
  notes.push(numberedD16?"Numbered D16 notation: faces 10 through 16 are entered as A through G; G maps to D++ face 0.":"Custom D++ D16 notation: faces use hexadecimal 0 through F.");
  if(finalRoll&&finalWord)notes.push(`Final D8 face ${finalRoll} selected checksum option ${finalRoll} of 8: ${finalWord}.`);
  if(waiting==="last-word")notes.push(`Choose 1 of ${config.candidates} checksum-valid final words to complete the ${config.words}-word seed.`);
  if(rejectedD8)notes.push(`Rejected ${rejectedD8} face${rejectedD8===1?"":"s"} that cannot be used for a D8 roll.`);
  if(rejectedD16)notes.push(`Rejected ${rejectedD16} face${rejectedD16===1?"":"s"} that ${rejectedD16===1?"is":"are"} not valid for the selected D16 convention (${numberedD16?"1–9 or A–G":"0–9 or A–F"}).`);
  if(extraAfter)warnings.push(`${extraAfter} extra input${extraAfter===1?" was":"s were"} ignored after ${config.words===24?"the final D8 roll":`the ${rolledTarget} rolled words`}.`);
  return{words,wordSlots,groups,group,finalEntry:finalEntry?.face||"",finalRoll,finalWord,candidates,waiting,currentPosition,activeGroupIndex,completedGroups,validWordCount,allRolledComplete,allRolledValid,bits,notes,warnings,invalidRanges,invalidCount:invalidRanges.length,invalidRequiredCount,rolledInvalidCount,needsCorrection:invalidRequiredCount>0,firstInvalid,rejectedD8,rejectedD16,extraAfter,acceptedCharacters,targetWords:config.words,neededPartial:rolledTarget,numberedD16,complete:allRolledValid&&config.words===24&&Boolean(finalWord)}
}
function hodlAnalyzeDiceInput(value,method=ge,targetWords=Pt,coinPositions=hodlDiceCoinPositions,numberedD16=hodlDPlusNumberedD16){
  if(method==="dplus"){
    let parsed=hodlDPlusRolls(value,targetWords,numberedD16);return{invalidRanges:parsed.invalidRanges,invalidCount:parsed.invalidCount,coinDerivedCount:0,acceptedRolls:parsed.acceptedCharacters,words:parsed.validWordCount,diceInWord:parsed.currentPosition??0,mappedBits:parsed.bits,totalMappedBits:parsed.bits,complete:parsed.complete,coinTurn:!1,dplus:parsed}
  }
  let config=hodlSeedConfig(targetWords),invalidRanges=[],acceptedRolls=[],coinPositionSet=new Set(coinPositions||[]),words=0,diceInWord=0,mappedBits=0,totalMappedBits=0;
  for(let index=0;index<value.length;){
    let character=String.fromCodePoint(value.codePointAt(index)),end=index+character.length,normalized=character.toLowerCase();
    if(/\s|,|;|\|/.test(character)){index=end;continue}
    let isDie=normalized>="1"&&normalized<="6",isCoin=normalized==="h"||normalized==="t",valid=!1;
    if(method==="coldcard"||method==="coleman"){valid=isDie&&!coinPositionSet.has(index);if(valid)acceptedRolls.push(normalized)}
    else if(words<config.partialWords){
      if(diceInWord<5){if(isDie&&Number(normalized)<=4){valid=!0;diceInWord+=1}}
      else if(isDie||isCoin){valid=!0;words+=1;diceInWord=0}
    }
    if(!valid)invalidRanges.push([index,end]);index=end
  }
  let coinDerivedCount=[...coinPositionSet].filter(index=>index>=0&&index<value.length).length;
  return{invalidRanges,invalidCount:invalidRanges.length,coinDerivedCount,acceptedRolls,words,diceInWord,mappedBits,totalMappedBits,complete:method==="bitbox"&&words>=config.partialWords,coinTurn:method==="bitbox"&&words<config.partialWords&&diceInWord===5}
}
function hodlRandomDiceFace(min,max){
  let size=max-min+1,cryptoObject=globalThis.crypto;if(!cryptoObject||typeof cryptoObject.getRandomValues!=="function")throw new Error("Secure random selection is unavailable in this browser.");
  let bytes=new Uint8Array(1),limit=Math.floor(256/size)*size;do{cryptoObject.getRandomValues(bytes)}while(bytes[0]>=limit);return min+bytes[0]%size
}
function hodlDiceControlValue(button){return button.dataset.coin==="heads"?String(hodlRandomDiceFace(1,3)):button.dataset.coin==="tails"?String(hodlRandomDiceFace(4,6)):button.dataset.d||""}
function hodlNormalizeDiceCoinPositions(positions){return[...new Set((positions||[]).filter(Number.isInteger).filter(index=>index>=0))].sort((a,b)=>a-b)}
function hodlRebaseDiceCoinPositions(start,end,insertedLength,markInserted=!1){
  let shift=insertedLength-(end-start),next=[];hodlDiceCoinPositions.forEach(index=>{if(index<start)next.push(index);else if(index>=end)next.push(index+shift)});if(markInserted)for(let index=0;index<insertedLength;index++)next.push(start+index);hodlDiceCoinPositions=hodlNormalizeDiceCoinPositions(next)
}
function hodlRememberDiceBeforeInput(input,event){
  input.hodlDiceBeforeInput={value:input.value,start:input.selectionStart??input.value.length,end:input.selectionEnd??input.selectionStart??input.value.length,inputType:event.inputType||""}
}
function hodlResolveDiceInputEdit(previous,current,pending){
  if(!pending||pending.value!==previous)return null;let start=Math.max(0,Math.min(previous.length,pending.start)),end=Math.max(start,Math.min(previous.length,pending.end)),removedLength=previous.length-current.length;
  if(start===end&&removedLength>0&&pending.inputType.startsWith("delete")){
    if(pending.inputType.endsWith("Backward"))start=Math.max(0,start-removedLength);
    else if(pending.inputType.endsWith("Forward"))end=Math.min(previous.length,end+removedLength);
    else return null
  }
  let insertedLength=current.length-(previous.length-(end-start));if(insertedLength<0||previous.slice(0,start)!==current.slice(0,start)||previous.slice(end)!==current.slice(start+insertedLength))return null;
  return{start,end,insertedLength}
}
function hodlTrackDiceInputEdit(input){
  let previous=input.dataset.previousValue??"",current=input.value,pending=input.hodlDiceBeforeInput;delete input.hodlDiceBeforeInput;let resolved=hodlResolveDiceInputEdit(previous,current,pending);
  if(resolved)hodlRebaseDiceCoinPositions(resolved.start,resolved.end,resolved.insertedLength,!1);
  else{let prefix=0;while(prefix<previous.length&&prefix<current.length&&previous[prefix]===current[prefix])prefix+=1;let previousEnd=previous.length,currentEnd=current.length;while(previousEnd>prefix&&currentEnd>prefix&&previous[previousEnd-1]===current[currentEnd-1]){previousEnd-=1;currentEnd-=1}hodlRebaseDiceCoinPositions(prefix,previousEnd,currentEnd-prefix,!1)}
  input.dataset.previousValue=current
}
function hodlSanitizeDiceInput(input,method=ge,targetWords=Pt,numberedD16=hodlDPlusNumberedD16){
  if(method==="dplus")return hodlSanitizeDPlusInput(input,targetWords,numberedD16);
  let raw=input.value,selectionStart=input.selectionStart??raw.length,selectionEnd=input.selectionEnd??selectionStart,selectionDirection=input.selectionDirection||"none",positions=new Set(hodlDiceCoinPositions),digits=[];
  for(let index=0;index<raw.length;index++)if(raw[index]>="1"&&raw[index]<="6")digits.push({value:raw[index],coin:positions.has(index)});
  let config=hodlSeedConfig(targetWords),clean="",nextPositions=[],digitEnds=[0],words=0,diceInWord=0,separateNext=!1;
  digits.forEach(digit=>{
    if(method==="bitbox"&&separateNext){clean+=" ";separateNext=!1}
    if(digit.coin)nextPositions.push(clean.length);clean+=digit.value;
    if(method==="bitbox"&&words<config.partialWords){
      if(diceInWord<5){if(Number(digit.value)<=4)diceInWord+=1}
      else{words+=1;diceInWord=0;separateNext=!0}
    }
    digitEnds.push(clean.length)
  });
  let countDigits=value=>value.replace(/[^1-6]/g,"").length,cleanSelectionStart=digitEnds[Math.min(countDigits(raw.slice(0,selectionStart)),digits.length)]??clean.length,cleanSelectionEnd=digitEnds[Math.min(countDigits(raw.slice(0,selectionEnd)),digits.length)]??clean.length,changed=raw!==clean;
  hodlDiceCoinPositions=hodlNormalizeDiceCoinPositions(nextPositions);input.dataset.previousValue=clean;delete input.hodlDiceBeforeInput;if(!changed)return!1;
  input.value=clean;input.setSelectionRange(cleanSelectionStart,cleanSelectionEnd,selectionDirection);return!0
}
function hodlSanitizeDPlusInput(input,targetWords=Pt,numberedD16=hodlDPlusNumberedD16){
  let raw=input.value,selectionStart=input.selectionStart??raw.length,selectionEnd=input.selectionEnd??selectionStart,selectionDirection=input.selectionDirection||"none",characters=[];
  for(let character of raw)if(/[0-9a-gA-G]/.test(character))characters.push(character.toUpperCase());
  let rolledCharacterTarget=hodlSeedConfig(targetWords).partialWords*3,clean="",characterEnds=[0];
  characters.forEach((character,index)=>{
    if(index>0&&(index<rolledCharacterTarget&&index%3===0||index===rolledCharacterTarget))clean+=" ";
    clean+=character;characterEnds.push(clean.length)
  });
  let countCharacters=value=>(value.match(/[0-9a-gA-G]/g)||[]).length,cleanSelectionStart=characterEnds[Math.min(countCharacters(raw.slice(0,selectionStart)),characters.length)]??clean.length,cleanSelectionEnd=characterEnds[Math.min(countCharacters(raw.slice(0,selectionEnd)),characters.length)]??clean.length,changed=raw!==clean;
  input.dataset.previousValue=clean;delete input.hodlDiceBeforeInput;if(!changed)return!1;
  input.value=clean;input.setSelectionRange(cleanSelectionStart,cleanSelectionEnd,selectionDirection);return!0
}
function hodlInsertDiceControl(input,button,update=hodlUpdateDice){
  let inserted;
  try{inserted=hodlDiceControlValue(button)}catch(error){let target=document.getElementById("error");if(target)target.textContent=error instanceof Error?error.message:String(error);return}
  let start=Number.isInteger(input.selectionStart)?input.selectionStart:input.value.length,end=Number.isInteger(input.selectionEnd)?input.selectionEnd:start;
  delete input.hodlDiceBeforeInput;if(ge!=="dplus")hodlRebaseDiceCoinPositions(start,end,inserted.length,Boolean(button.dataset.coin));input.value=input.value.slice(0,start)+inserted+input.value.slice(end);input.dataset.previousValue=input.value;
  let caret=start+inserted.length;input.focus({preventScroll:!0});input.setSelectionRange(caret,caret);hodlSanitizeDiceInput(input);update()
}
function hodlInsertEntropyControl(input,button){
  let inserted=button.dataset.entropyDigit||button.dataset.vkCharacter||"";if(!input||!inserted)return;
  let start=Number.isInteger(input.selectionStart)?input.selectionStart:input.value.length,end=Number.isInteger(input.selectionEnd)?input.selectionEnd:start;
  input.focus({preventScroll:!0});input.setRangeText(inserted,start,end,"end");input.dispatchEvent(new InputEvent("input",{bubbles:!0,inputType:"insertText",data:inserted}))
}
function hodlSyncDiceHighlight(input){
  let highlight=input.closest(".dice-input-shell")?.querySelector(".dice-input-highlight");if(!highlight)return;highlight.scrollTop=input.scrollTop;highlight.scrollLeft=input.scrollLeft
}
function hodlRenderInputHighlight(input,ranges=[]){
  let highlight=input.closest(".dice-input-shell")?.querySelector(".dice-input-highlight");if(!highlight)return;let fragment=document.createDocumentFragment(),cursor=0,normalized=ranges.map(range=>[Math.max(0,Number(range[0])||0),Math.min(input.value.length,Number(range[1])||0)]).filter(([start,end])=>end>start).sort((a,b)=>a[0]-b[0]);
  normalized.forEach(([rangeStart,rangeEnd])=>{let start=Math.max(cursor,rangeStart),end=Math.max(start,rangeEnd);if(start>cursor)fragment.appendChild(document.createTextNode(input.value.slice(cursor,start)));if(end>start){let span=document.createElement("span");span.className="dice-roll-invalid";span.textContent=input.value.slice(start,end);fragment.appendChild(span);cursor=end}});
  if(cursor<input.value.length)fragment.appendChild(document.createTextNode(input.value.slice(cursor)));highlight.dataset.trailingNewline=String(input.value.endsWith("\n"));highlight.replaceChildren(fragment);hodlSyncDiceHighlight(input);requestAnimationFrame(()=>hodlSyncDiceHighlight(input))
}
function hodlRenderDiceInputHighlight(input,analysis){hodlRenderInputHighlight(input,analysis.invalidRanges)}
function hodlBinaryDigits(value){return String(value??"").replace(/[^01]/g,"")}
function hodlGroupedBinary(value){let digits=hodlBinaryDigits(value),groups=digits.match(/.{1,11}/g);return groups?groups.join(" "):""}
function hodlBinarySelectionOffset(bitCount,totalBits){let separators=totalBits>0?Math.floor((totalBits-1)/11):0;return bitCount+Math.min(Math.floor(bitCount/11),separators)}
function hodlFormatBinaryInput(input){
  let raw=input.value,grouped=hodlGroupedBinary(raw);if(grouped===raw)return!1;let start=input.selectionStart??raw.length,end=input.selectionEnd??start,direction=input.selectionDirection||"none",startBits=hodlBinaryDigits(raw.slice(0,start)).length,endBits=hodlBinaryDigits(raw.slice(0,end)).length,totalBits=hodlBinaryDigits(raw).length;
  input.value=grouped;input.setSelectionRange(hodlBinarySelectionOffset(startBits,totalBits),hodlBinarySelectionOffset(endBits,totalBits),direction);return!0
}
function hodlHandleGroupedSeparatorDelete(input,event){
  if(input.selectionStart!==input.selectionEnd)return;let caret=input.selectionStart??0,start=caret,end=caret;
  if(event.inputType==="deleteContentBackward"&&caret>1&&input.value[caret-1]===" ")start=caret-2;
  else if(event.inputType==="deleteContentForward"&&input.value[caret]===" "&&caret+1<input.value.length)end=caret+2;
  else return;event.preventDefault();input.setRangeText("",start,end,"end");input.dispatchEvent(new InputEvent("input",{bubbles:!0,inputType:event.inputType}))
}
function hodlHandleBinarySeparatorDelete(input,event){hodlHandleGroupedSeparatorDelete(input,event)}
function hodlAnalyzeEntropyInput(value,format,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),limit=format==="bin"?config.bits:config.hexChars,count=0,invalidRanges=[];
  for(let index=0;index<value.length;index++){if(/\s/.test(value[index]))continue;if(count>=limit)invalidRanges.push([index,index+1]);count+=1}
  return{count,limit,excessCount:Math.max(0,count-limit),invalidRanges}
}
function hodlRenderEntropyInputState(input,format,targetWords=Pt){let analysis=hodlAnalyzeEntropyInput(input.value,format,targetWords);hodlRenderInputHighlight(input,analysis.invalidRanges);return analysis}
function hodlUpdateDiceButtons(input,analysis){
  let pad=input.closest("#form")?.querySelector(".dice-input-pad");if(!pad)return;pad.querySelectorAll("button[data-d]").forEach(button=>{
    let disabled=!1,reason="";
    if(ge==="dplus"){
      let turn=analysis.dplus?.waiting||"d8",isD8=turn==="d8"||turn==="checksum-d8",correcting=turn==="correction",value=String(button.dataset.d||"").toUpperCase();
      disabled=turn==="complete"||turn==="last-word"||correcting||(isD8&&!/^[1-8]$/.test(value))||(!isD8&&!correcting&&hodlDPlusD16Value(value)===null);
      if(turn==="complete")reason="The rolled words and final D8 checksum roll are complete.";
      else if(turn==="last-word")reason=`All ${hodlSeedConfig().partialWords} rolled words are complete. Choose the final checksum word below.`;
      else if(correcting)reason="Correct the highlighted invalid face in its existing D++ position before continuing.";
      else if(disabled)reason="This roll needs the D8, so use a face from 1 through 8.";
      else reason=isD8?(turn==="checksum-d8"?"Final D8: choose checksum option 1 through 8.":"D8 roll: choose face 1 through 8."):hodlDPlusNumberedD16?"Numbered D16 roll: choose face 1 through 16; the transcript uses A through G for 10 through 16.":"Custom D++ D16 roll: choose any hexadecimal face from 0 through F.";
    }else if(ge==="bitbox"){
      let face=Number(button.dataset.d);
      if(analysis.complete){disabled=!0;reason="All lookup-table words are complete."}
      else if(button.dataset.coin){disabled=!analysis.coinTurn;if(disabled)reason="Heads and Tails are available after five valid rolls of 1–4."}
      else if(!analysis.coinTurn&&face>=5){disabled=!0;reason="Reroll a 5 or 6 during the first five BitBox rolls."}
    }else if(button.dataset.coin){disabled=!0;reason="Heads and Tails are available in BitBox-style mode."}
    button.disabled=disabled;button.title=reason
  })
}
function hodlRenderDiceInputState(input){
  let analysis=hodlAnalyzeDiceInput(input.value,ge,Pt);input.setAttribute("aria-invalid",String(analysis.invalidCount>0));hodlRenderDiceInputHighlight(input,analysis);hodlUpdateDiceButtons(input,analysis);return analysis
}
function hodlIanColemanDiceString(rolls){return rolls.map(face=>face==="6"?"0":face).join("")}
function hodlBitsToTargetEntropy(bitString,sourceBits,method,notes,warnings,targetWords,allowExtra){
  let config=hodlSeedConfig(targetWords);
  if(bitString.length<config.bits)return{ok:!1,error:`Need ${config.bits} mapped bits for a ${config.words}-word seed. This input provides ${bitString.length}.`,notes,warnings};
  if(!allowExtra&&bitString.length!==config.bits)return{ok:!1,error:`The selected ${config.words}-word seed needs exactly ${config.bits} bits. You entered ${bitString.length}.`,notes,warnings};
  if(bitString.length>config.bits)warnings.push(`Using the first ${config.bits} mapped bits of ${bitString.length}. Extra bits are not mixed in.`);
  let selected=bitString.slice(0,config.bits),bytes=new Uint8Array(config.bytes);
  for(let index=0;index<bytes.length;index++)bytes[index]=Number.parseInt(selected.slice(index*8,index*8+8),2);
  notes.push(`BIP39 entropy length: ${config.bits} bits \u2192 ${config.words}-word seed.`);
  return{ok:!0,bytes,hex:M.encode(bytes),bits:config.bits,sourceBits,method,notes,warnings}
}
function hodlDiceEntropy(value,method,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),notes=[],warnings=[];
  if(method==="dplus")return{ok:!1,error:`D++ directly selects ${config.partialWords} BIP39 words, then ${config.words===24?"uses a final D8 roll":"uses a checksum-valid word selection"} for the final word.`,notes,warnings};
  let parsed=Br(value),rolls=parsed.rolls;
  if(method==="bitbox")return{ok:!1,error:`BitBox diceware uses ${config.partialWords} lookup-table words and a final checksum pick for a ${config.words}-word seed.`,notes,warnings};
  if(parsed.leftover.length)return{ok:!1,error:`Dice must be faces 1\u20136. Ignored characters: ${JSON.stringify(parsed.leftover.slice(0,24))}`,notes,warnings};
  if(!rolls.length)return{ok:!1,error:"Enter at least one dice roll (faces 1\u20136).",notes,warnings};
  let sourceBits=kr(rolls.length);notes.push(`${rolls.length} rolls of a fair six-sided die \u2248 ${sourceBits.toFixed(1)} bits.`);
  if(rolls.length<config.hashRolls)warnings.push(`Only ${rolls.length} of ${config.hashRolls} recommended fair-die rolls were entered. The ${config.words}-word phrase is deterministic, but its security cannot exceed the approximately ${sourceBits.toFixed(1)} bits supplied. Use only for testing until the recommendation is met.`);
  else if(rolls.length>config.hashRolls)notes.push(`All ${rolls.length} rolls, including ${rolls.length-config.hashRolls} beyond the recommendation, are included in the hash.`);
  let hashInput=method==="coleman"?hodlIanColemanDiceString(rolls):rolls.join(""),digest=Z(new TextEncoder().encode(hashInput)),bytes=digest.slice(0,config.bytes);
  if(method==="coleman")notes.push(`Hashed rolls / Dice [1-6]: convert every 6 to 0, SHA-256 hash the complete mapped digit string, then use the first ${config.bits} bits for the selected ${config.words}-word seed. This matches the method used by Keystone.`);
  else notes.push(`Hashed rolls / Base 10 [0-9]: SHA-256 hash the complete original dice digit string, then use the first ${config.bits} bits for the selected ${config.words}-word seed. This matches COLDCARD and SeedSigner.`);
  return{ok:!0,bytes,hex:M.encode(bytes),bits:config.bits,sourceBits,method:method==="coleman"?"ian-coleman-dice-sha256":"coldcard-sha256",notes,warnings}
}
function hodlHexEntropy(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),notes=[],warnings=[],compact=value.replace(/\s|_/g,"").replace(/^0x/i,"").toLowerCase();
  if(!compact)return{ok:!1,error:`Enter exactly ${config.hexChars} hexadecimal characters for a ${config.words}-word seed.`,notes,warnings};
  if(!/^[0-9a-f]+$/.test(compact))return{ok:!1,error:"Hex entropy may only contain 0\u20139 and a\u2013f.",notes,warnings};
  if(compact.length!==config.hexChars)return{ok:!1,error:`The selected ${config.words}-word seed needs exactly ${config.hexChars} hex characters (${config.bits} bits). You entered ${compact.length}.`,notes,warnings};
  let bytes=M.decode(compact);notes.push(`${bytes.length} bytes = ${config.bits} bits of hex entropy.`);notes.push(`BIP39 entropy length: ${config.bits} bits \u2192 ${config.words}-word seed.`);
  return{ok:!0,bytes,hex:M.encode(bytes),bits:config.bits,sourceBits:config.bits,method:"hex",notes,warnings}
}
function hodlBinaryEntropy(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),notes=[],warnings=[],compact=value.replace(/\s/g,"");
  if(!compact)return{ok:!1,error:`Enter exactly ${config.bits} zeros and ones for a ${config.words}-word seed.`,notes,warnings};
  if(!/^[01]+$/.test(compact))return{ok:!1,error:"Binary entropy may only contain 0 and 1.",notes,warnings};
  if(compact.length!==config.bits)return{ok:!1,error:`The selected ${config.words}-word seed needs exactly ${config.bits} binary digits. You entered ${compact.length}.`,notes,warnings};
  notes.push(`${compact.length} coin-flip bits.`);
  return hodlBitsToTargetEntropy(compact,compact.length,"binary",notes,warnings,config.words,!1)
}
function hodlSeedCountStatus(count,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),entered=Math.max(0,Number(count)||0);
  return entered<=config.words?`${entered} of ${config.words} BIP39 words entered`:`${entered} entered \u00b7 ${config.words} required BIP39 words`
}
function hodlValidateTargetMnemonic(value,targetWords=Pt){
  let words=Rn(value).split(" ").filter(Boolean),config=hodlSeedConfig(targetWords);
  if(!words.length)return{ok:!1,words,error:`${hodlSeedCountStatus(0,config.words)} \u00b7 ${config.words} remaining`,unknown:[]};
  if(words.length!==config.words){let difference=config.words-words.length,error=difference>0?`${hodlSeedCountStatus(words.length,config.words)} \u00b7 ${difference} remaining`:`${hodlSeedCountStatus(words.length,config.words)} \u00b7 ${-difference} extra word${difference===-1?"":"s"} must be removed`;return{ok:!1,words,error,unknown:[]}}
  return Mt(words.join(" "))
}
function hodlTargetLastWords(value,targetWords=Pt){
  let words=Rn(value).split(" ").filter(Boolean),config=hodlSeedConfig(targetWords);
  if(words.length!==config.partialWords)return null;
  let result=Tr(words.join(" "));
  return result&&result.completeCount===config.words?result:null
}
function hodlSeedFinalWordContext(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),tokens=[...String(value??"").matchAll(/\S+/g)].map(match=>({word:match[0].toLowerCase(),start:match.index,end:match.index+match[0].length}));
  if(tokens.length<config.partialWords||tokens.length>config.words)return null;
  let baseTokens=tokens.slice(0,config.partialWords);if(baseTokens.some(token=>!hodlBip39WordSet.has(token.word)))return null;
  let result=Tr(baseTokens.map(token=>token.word).join(" "));if(!result||result.error||result.completeCount!==config.words)return null;
  let finalToken=tokens[config.partialWords]??null,prefix=finalToken?.word??"",matchingCandidates=prefix?result.candidates.filter(word=>word.startsWith(prefix)):result.candidates.slice();
  return{baseWords:baseTokens.map(token=>token.word),candidates:result.candidates,finalToken,prefix,matchingCandidates,selected:result.candidates.includes(prefix)?prefix:"",targetWords:config.words}
}
function hodlAnalyzeSeedInput(input,targetWords=Pt){
  let value=input.value,config=hodlSeedConfig(targetWords);if(hodlLooksExtendedKey(value))return{tokens:[],invalidRanges:[],invalidWords:[],excessCount:0,checksumInvalid:!1,extendedKey:!0};
  let tokens=[...value.matchAll(/\S+/g)].map(match=>({word:match[0].toLowerCase(),start:match.index,end:match.index+match[0].length})),invalidRanges=[],invalidWords=[],excessCount=0,lastIndex=tokens.length-1,last=tokens[lastIndex],activePrefix=Boolean(last&&document.activeElement===input&&!/\s$/.test(value)&&input.selectionStart===input.selectionEnd&&input.selectionStart===last.end);
  let finalContext=hodlSeedFinalWordContext(value,config.words);
  tokens.forEach((token,index)=>{let listed=hodlBip39WordSet.has(token.word),options=index===config.partialWords&&finalContext?finalContext.candidates:Ae,viablePrefix=activePrefix&&index===lastIndex&&token.word.length>0&&options.some(word=>word.startsWith(token.word));if(index>=config.words){invalidRanges.push([token.start,token.end]);excessCount+=1}else if(!listed&&!viablePrefix){invalidRanges.push([token.start,token.end]);invalidWords.push({index,word:token.word})}});
  let checksumInvalid=!1,allListed=tokens.length===config.words&&tokens.every(token=>hodlBip39WordSet.has(token.word)),finalCanContinue=Boolean(activePrefix&&finalContext?.prefix&&finalContext.matchingCandidates.some(word=>word!==finalContext.prefix));
  if(allListed&&!Pn(tokens.map(token=>token.word).join(" "),Ae)&&!finalCanContinue){checksumInvalid=!0;let final=tokens[tokens.length-1];invalidRanges.push([final.start,final.end])}
  return{tokens,invalidRanges,invalidWords,excessCount,checksumInvalid,extendedKey:!1}
}
function hodlRenderSeedInputState(input,targetWords=Pt){let analysis=hodlAnalyzeSeedInput(input,targetWords);input.setAttribute("aria-invalid",String(analysis.invalidRanges.length>0));hodlRenderInputHighlight(input,analysis.invalidRanges);return analysis}
function hodlApplyFilteredInput(input,filter){
  let value=input.value,clean=filter(value);if(clean===value)return!1;let start=input.selectionStart??value.length,end=input.selectionEnd??start,direction=input.selectionDirection||"none";
  input.value=clean;input.setSelectionRange(filter(value.slice(0,start)).length,filter(value.slice(0,end)).length,direction);return!0
}
function hodlAutocompleteSeedInput(input,event){
  let toggle=document.getElementById("seed-autocomplete");if(!toggle?.checked||event?.inputType!=="insertText"||event.isComposing||input.selectionStart!==input.selectionEnd)return!1;
  let caret=input.selectionStart??input.value.length,suffix=input.value.slice(caret);if(suffix&&!/^\s/.test(suffix))return!1;
  let match=input.value.slice(0,caret).match(/([A-Za-z]+)$/);if(!match)return!1;let prefix=match[1].toLowerCase(),start=caret-match[1].length,finalContext=hodlSeedFinalWordContext(input.value,Pt),isFinalPrefix=Boolean(finalContext?.finalToken&&finalContext.finalToken.start===start&&finalContext.finalToken.end===caret),options=isFinalPrefix?finalContext.candidates:Ae,minimumLength=isFinalPrefix?1:2;
  if(prefix.length<minimumLength)return!1;let matches=options.filter(word=>word.startsWith(prefix));if(matches.length!==1)return!1;
  let replacement=matches[0]+(suffix?"":" ");input.setRangeText(replacement,start,caret,"end");return!0
}
function hodlReplaceSeedFinalWord(input,context,word){
  if(!input||!context)return;input.value=[...context.baseWords,...(word?[word]:[])].join(" ");input.setSelectionRange(input.value.length,input.value.length);
  input.dispatchEvent(new InputEvent("input",{bubbles:!0,inputType:"insertReplacementText",data:word||null}))
}
function hodlBitBoxRolls(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),words=[],skippedHigh=0,leftover="",extraAfter=0,diceInWord=[],notes=[],warnings=[];
  for(let character of value){
    if(/\s|,|;|\|/.test(character))continue;
    let input=character.toLowerCase(),isDie=input>="1"&&input<="6",isCoin=input==="h"||input==="t";
    if(!isDie&&!isCoin){leftover+=character;continue}
    if(words.length>=config.partialWords){extraAfter+=1;continue}
    if(diceInWord.length<5){
      if(isCoin){leftover+=character;continue}
      let face=Number(input);if(face>=5){skippedHigh+=1;continue}diceInWord.push(face);continue
    }
    let coin=input==="h"||input==="1"||input==="2"||input==="3"?0:1;
    words.push(mi(diceInWord,coin));diceInWord=[]
  }
  let waiting=words.length>=config.partialWords?"last-word":diceInWord.length===5?"coin":"dice",bits=words.length*11;
  notes.push(`BitBox diceware: ${words.length} of ${config.partialWords} lookup-table words (${bits} encoded bits). Then choose the final checksum word.`);
  if(skippedHigh)notes.push(`Skipped ${skippedHigh} face${skippedHigh===1?"":"s"} of 5 or 6 on the first five dice of a word (reroll).`);
  if(extraAfter)warnings.push("Extra rolls after the final lookup-table word are ignored. The checksum word is a separate pick, not another roll.");
  if(leftover.length)warnings.push(`Ignored characters: ${JSON.stringify(leftover.slice(0,24))}`);
  return{words,targetWords:config.words,neededPartial:config.partialWords,skippedHigh,leftover,extraAfter,waiting,diceInWord:diceInWord.length,bits,notes,warnings}
}
function hodlDicePreviewWords(value,method,targetWords=Pt){
  let config=hodlSeedConfig(targetWords);
  if(method==="dplus"){let parsed=hodlDPlusRolls(value,targetWords);return[...parsed.wordSlots,...(parsed.finalWord?[parsed.finalWord]:[])]}
  let parsed=Br(value),analysis=hodlAnalyzeDiceInput(value,method,targetWords);if(parsed.leftover.length||analysis.coinDerivedCount||!parsed.rolls.length)return[];let bytes;
  if(method==="coldcard")bytes=Z(new TextEncoder().encode(parsed.rolls.join(""))).slice(0,config.bytes);
  else if(method==="coleman")bytes=Z(new TextEncoder().encode(hodlIanColemanDiceString(parsed.rolls))).slice(0,config.bytes);
  else return[];
  try{return _n(bytes).split(" ")}catch{return[]}
}
function hodlBinaryPreviewWords(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),digits=hodlBinaryDigits(value).slice(0,config.bits);if(!digits.length)return[];
  if(digits.length>=config.bits){
    let bytes=new Uint8Array(config.bytes);for(let index=0;index<bytes.length;index++)bytes[index]=Number.parseInt(digits.slice(index*8,index*8+8),2);
    try{return _n(bytes).split(" ")}catch{return[]}
  }
  let words=[],completeGroups=Math.min(config.partialWords,Math.floor(digits.length/11));
  for(let index=0;index<completeGroups;index++)words.push(Ae[Number.parseInt(digits.slice(index*11,index*11+11),2)]);
  return words
}
function hodlHexPreviewWords(value,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),digits=String(value??"").replace(/[^0-9a-f]/gi,"").slice(0,config.hexChars);
  let bits=Array.from(digits,digit=>Number.parseInt(digit,16).toString(2).padStart(4,"0")).join("");
  return hodlBinaryPreviewWords(bits,config.words)
}
function hodlRenderDiceWordGrid(container,words,targetWords=Pt,provisional=!1){
  if(!container)return;let config=hodlSeedConfig(targetWords),values=Array.isArray(words)?words:[],fragment=document.createDocumentFragment();container.innerHTML="";
  container.style.setProperty("--dice-word-rows-wide",String(Math.ceil(config.words/3)));container.style.setProperty("--dice-word-rows-narrow",String(Math.ceil(config.words/2)));
  container.setAttribute("aria-label",`${config.words} seed-word slots${provisional?", provisional preview":""}`);container.dataset.provisional=String(provisional);
  for(let index=0;index<config.words;index++){
    let word=values[index]||"",slot=document.createElement("div"),number=document.createElement("span"),value=document.createElement("span");slot.className="dice-word-slot"+(word?"":" empty");slot.dataset.wordSlot=String(index+1);
    number.className="dice-word-number";number.textContent=`${index+1}.`;value.className="dice-word-value";value.dataset.word="";value.textContent=word||"\u2014";slot.append(number,value);fragment.appendChild(slot)
  }
  container.appendChild(fragment)
}
function hodlUpdateEntropyInput(input,format,targetWords=Pt){
  let config=hodlSeedConfig(targetWords),analysis=hodlRenderEntropyInputState(input,format,config.words),meta=document.getElementById("entropy-meta"),ready=analysis.count===analysis.limit,hasExcess=analysis.excessCount>0;
  input.setAttribute("aria-invalid",String(hasExcess));
  if(format==="bin"){
    let words=hodlBinaryPreviewWords(input.value,config.words),wordsBox=document.getElementById("entropy-words"),status=hasExcess?`${analysis.count} entered · ${analysis.limit} required binary digits · ${analysis.excessCount} extra highlighted · remove to continue`:`${analysis.count} of ${analysis.limit} binary digits · ${words.length} of ${config.words} seed words filled${ready?" · ready to derive":""}`;
    if(meta){meta.textContent=status;meta.className="muted"+(ready?" ok":hasExcess?" err":"")}
    hodlRenderDiceWordGrid(wordsBox,words,config.words,!1)
  }else{
    let words=hodlHexPreviewWords(input.value,config.words),wordsBox=document.getElementById("entropy-words"),status=hasExcess?`${analysis.count} entered · ${analysis.limit} required hexadecimal characters · ${analysis.excessCount} extra highlighted · remove to continue`:`${analysis.count} of ${analysis.limit} hexadecimal characters · ${words.length} of ${config.words} seed words filled${ready?" · ready to derive":""}`;
    if(meta){meta.textContent=status;meta.className="muted"+(ready?" ok":hasExcess?" err":"")}
    hodlRenderDiceWordGrid(wordsBox,words,config.words,!1)
  }
  return analysis
}
function hodlRenderLastWordPicker(container,candidates,selected,onPick,settings={}){
  if(!container)return;container.innerHTML="";if(!candidates||!candidates.length)return;
  if(candidates.length<=16&&!settings.forceSelect){
    container.innerHTML=candidates.map(word=>`<button type="button" class="tab${word===selected?" active":""}" data-lw="${word}" aria-pressed="${word===selected}">${word}</button>`).join("");
    container.querySelectorAll("[data-lw]").forEach(button=>{button.onclick=()=>onPick(button.dataset.lw||"")});return
  }
  let targetWords=Number(settings.targetWords)||Pt,label=document.createElement("label"),select=document.createElement("select"),placeholderValue="__entropylab_placeholder__";
  label.className="field last-word-field";label.textContent=`Valid final word (${candidates.length} choices)`;select.setAttribute("aria-label",`Valid final word for ${targetWords}-word seed`);
  if(!selected){let placeholder=document.createElement("option");placeholder.value=placeholderValue;placeholder.textContent=settings.placeholder||"Choose a confirmed final word";placeholder.disabled=!0;placeholder.selected=!0;placeholder.dataset.customSelectPlaceholder="true";select.appendChild(placeholder)}
  if(settings.resettable){let reset=document.createElement("option");reset.value="";reset.textContent="-";select.appendChild(reset)}
  candidates.forEach(word=>{let option=document.createElement("option");option.value=word;option.textContent=word;option.selected=word===selected;select.appendChild(option)});
  select.onchange=()=>{if(select.value!==placeholderValue)onPick(select.value)};label.appendChild(select);container.appendChild(label)
}
function hodlUpdateSeedLengthControl(){
  let section=document.getElementById("seed-length");if(!section)return;let config=hodlSeedConfig();section.hidden=Ne==="key";
  section.querySelectorAll("[data-seed-words]").forEach(button=>{let active=Number(button.dataset.seedWords)===config.words;button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active))});
  let help=document.getElementById("seed-length-help");if(!help)return;
  help.textContent=Ne==="hex"?(hodlEntropyFormat==="bin"?`${config.words} words require exactly ${config.bits} binary digits.`:`${config.words} words require exactly ${config.hexChars} hexadecimal characters.`):Ne==="seed"?`Enter exactly ${config.words} BIP39 words. Extended keys ignore this selection.`:`${config.words} words use ${config.bits} bits of BIP39 entropy.`
}
function hodlInvalidateActiveKeyOutput(){
  re=null;Ge=!1;ft="";dr.innerHTML="";let error=document.getElementById("error");if(error)error.textContent="";
  let state=hodlKeys[hodlActiveKey];if(state){state.result=null;state.reveal=!1;state.lastWord="";state.dplusLastWord="";state.error=""}
}
function hodlSetSeedLength(words){
  let config=hodlSeedLengths[Number(words)];if(!config)return;if(Pt===config.words){hodlUpdateSeedLengthControl();hodlQueueMasterFingerprintPreview(0);return}
  hodlCaptureKey();let state=hodlKeys[hodlActiveKey];Pt=config.words;hodlInvalidateActiveKeyOutput();
  if(state){state.targetWords=config.words;state.diceMethod=ge;state.lastWord="";state.dplusLastWord="";state.result=null;state.reveal=!1;state.error=""}
  hodlRenderKeyForm();hodlRestoreFormFields(state);hodlUpdateSeedLengthControl();hodlQueueMasterFingerprintPreview(0)
}
function hodlRenderKeyForm(){
  let config=hodlSeedConfig();hodlUpdateSeedLengthControl();
  if(Ne==="dice"){
    let dplusFaces=["1","2","3","4","5","6","7","8","9","A","B","C","D","E","F",hodlDPlusNumberedD16?"G":"0"],dplusPad=(hodlPadShuffle?hodlShuffle(dplusFaces):dplusFaces).map(face=>{let decimal=face==="G"?16:Number.parseInt(face,16),label=decimal>=10?`${decimal} (${face})`:face,aria=face==="G"?"Numbered D16 face 16, entered as G":`D16 face ${face}${decimal>=10?`, decimal ${decimal}`:""}`;return`<button type="button" data-d="${face}" aria-label="${aria}">${label}</button>`}).join("");
    let diceLabel=ge==="dplus"?(config.words===24?"D++ rolls (D8, D16, D16; then a final D8)":"D++ rolls (D8, D16, D16)"):ge==="bitbox"?"Dice rolls (1–4, then coin / 6th die)":"Dice rolls (faces 1–6 only)";
    let diceHelp=ge==="dplus"?`For each of the first ${config.partialWords} words, enter the D8 face (1–8), then both D16 faces (${hodlDPlusNumberedD16?"1–9 or A–G; G represents 16 and maps to D++ face 0":"0–9 or A–F, following the custom D++ die"}). Each three-character group is positional: an invalid face stays in its original slot until you correct it. ${config.words===24?"The final D8 roll selects one of the eight checksum-valid 24th words.":`Then choose 1 of ${config.candidates} checksum-valid final words from the dropdown using your own offline randomness.`} Letters are stored as uppercase.`:ge==="bitbox"?`${config.partialWords} lookup-table words fill one slot at a time, then choose a confirmed final checksum word. Use 1–4 for the first five rolls. On the sixth, Heads inserts an equivalent face from 1–3 and Tails inserts one from 4–6; that numeric choice does not add entropy.`:ge==="coleman"?`Every rolled 6 becomes 0 before the complete digit string is hashed with SHA-256. This Dice [1-6] method matches the method used by Keystone. Any nonempty count produces a phrase, but use at least ${config.hashRolls} fair rolls before relying on it.`:`The original dice digit string is hashed with SHA-256. This Base 10 [0-9] method matches COLDCARD and SeedSigner. Any nonempty count produces a phrase, but use at least ${config.hashRolls} fair rolls before relying on it.`;
    let dicePlaceholder=ge==="dplus"?`e.g. ${hodlDPlusNumberedD16?"1GG":"100"} 2AF …${config.words===24?" then final D8":""}`:ge==="bitbox"?"111111 222224…":"e.g. 415263415263…";
    let dicePad=ge==="dplus"?`<div class="dice-input-pad dplus">${dplusPad}</div>`:`<div class="dice-input-pad dice-digits">${(hodlPadShuffle?hodlShuffle([1,2,3,4,5,6]):[1,2,3,4,5,6]).map(face=>`<button type="button" data-d="${face}">${face}</button>`).join("")}<button type="button" class="coin-button" data-d="H" data-coin="heads">Heads (1–3)</button><button type="button" class="coin-button" data-d="T" data-coin="tails">Tails (4–6)</button></div>`;
    let dplusConvention=ge==="dplus"?`<label class="seed-autocomplete-toggle"><input type="checkbox" id="dplus-numbered-d16" ${hodlDPlusNumberedD16?"checked":""} /><span>Use a numbered D16 (1–16) <span class="seed-autocomplete-note">(enter 10–16 as A–G; G maps to D++ face 0)</span></span></label>`:"";
    at.innerHTML=`
      <p class="label">How to turn rolls into a ${config.words}-word seed</p>
      <div class="choice-grid">
      <label class="choice"><input type="radio" name="dm" value="coldcard" ${ge==="coldcard"?"checked":""} />
        <span><strong>Hashed rolls / Base 10 [0-9] (recommended)</strong><span class="desc">SHA-256 of the original dice digit string, matching the method used by COLDCARD and SeedSigner. The first ${config.bits} bits become the selected ${config.words}-word seed; ${config.hashRolls} rolls are recommended, and every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="coleman" ${ge==="coleman"?"checked":""} />
        <span><strong>Hashed rolls / Dice [1-6]</strong><span class="desc">Convert each 6 to 0 and SHA-256 the complete mapped digit string, matching the method used by Keystone. Use the first ${config.bits} bits; ${config.hashRolls} rolls are recommended, and every entered roll is included.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="bitbox" ${ge==="bitbox"?"checked":""} />
        <span><strong>BitBox diceware / Direct word selection</strong><span class="desc">Use five dice showing 1\u20134, then a coin (or 6th die: 1\u20133 heads, 4\u20136 tails). Build ${config.partialWords} lookup-table words, then choose 1 of ${config.candidates} valid final checksum words.</span></span>
      </label>
      <label class="choice"><input type="radio" name="dm" value="dplus" ${ge==="dplus"?"checked":""} />
        <span><strong>D++ / Direct word selection</strong><span class="desc">Roll one 8-sided die and two 16-sided dice for each of the first ${config.partialWords} words, then ${config.words===24?"roll the D8 once more to select the checksum-valid final word":`choose 1 of ${config.candidates} checksum-valid final words from the dropdown`}.</span></span>
      </label>
      </div>
      <p class="label" id="dice-label">${diceLabel}</p>
      <p class="muted" id="dice-help">${diceHelp}</p>
      ${dplusConvention}
      <div class="dice-input-shell"><pre class="dice-input-highlight" id="dice-highlight" aria-hidden="true"></pre><textarea id="dice" placeholder="${dicePlaceholder}" aria-describedby="dice-help dice-meta"></textarea></div>
      ${dicePad}
      <label class="pad-shuffle-toggle"><input type="checkbox" id="pad-shuffle-toggle" ${hodlPadShuffle?"checked":""} /><span>Shuffle pad keys <span class="seed-autocomplete-note">(reorders the digit keys; Heads/Tails stay fixed)</span></span></label>
      <p class="muted" id="dice-meta" aria-live="polite"></p>
      <div id="dice-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div><div id="last-words" class="row" style="margin-top:8px"></div>`;
    let input=document.getElementById("dice");input.dataset.previousValue=input.value;
    at.querySelectorAll("[data-d]").forEach(button=>{button.onclick=()=>hodlInsertDiceControl(input,button)});
    let shuffleToggle=at.querySelector("#pad-shuffle-toggle");if(shuffleToggle)shuffleToggle.onchange=()=>{hodlCaptureKey();let state=hodlKeys[hodlActiveKey];hodlPadShuffle=shuffleToggle.checked;if(state)state.padShuffle=hodlPadShuffle;hodlRenderKeyForm();hodlRestoreFormFields(state);hodlUpdateDice()};
    input.oninput=()=>{if(ge!=="dplus")hodlTrackDiceInputEdit(input);else delete input.hodlDiceBeforeInput;hodlSanitizeDiceInput(input);hodlUpdateDice()};input.onscroll=()=>hodlSyncDiceHighlight(input);
    let dplusToggle=document.getElementById("dplus-numbered-d16");if(dplusToggle)dplusToggle.onchange=()=>{
      let state=hodlKeys[hodlActiveKey],selectionStart=input.selectionStart??input.value.length,selectionEnd=input.selectionEnd??selectionStart,selectionDirection=input.selectionDirection||"none",translated=hodlTranslateDPlusD16Notation(input.value);
      hodlDPlusNumberedD16=dplusToggle.checked;if(state){state.dplusNumberedD16=hodlDPlusNumberedD16;state.fields.dplusDice=translated}
      hodlInvalidateLiveKeyResult();hodlRenderKeyForm();hodlRestoreFormFields(state);let replacement=document.getElementById("dice");if(replacement)replacement.setSelectionRange(Math.min(selectionStart,replacement.value.length),Math.min(selectionEnd,replacement.value.length),selectionDirection);hodlUpdateDice();hodlQueueMasterFingerprintPreview(0)
    };
    at.querySelectorAll("input[name=dm]").forEach(radio=>{radio.onchange=()=>{
      let raw=input.value,lastWord=ft,previousMethod=ge,state=hodlKeys[hodlActiveKey];
      if(state){if(previousMethod==="dplus"){state.fields.dplusDice=raw;state.dplusLastWord=lastWord}else{state.fields.dice=raw;state.diceCoinPositions=hodlDiceCoinPositions.slice();if(previousMethod==="bitbox")state.lastWord=lastWord}}
      ge=radio.value;if(state){state.diceMethod=ge;ft=ge==="dplus"?state.dplusLastWord||"":ge==="bitbox"?state.lastWord||"":""}else ft=previousMethod===ge?lastWord:"";hodlRenderKeyForm();
      let replacement=document.getElementById("dice"),replacementValue=state?(ge==="dplus"?state.fields.dplusDice||"":state.fields.dice||""):(previousMethod===ge?raw:"");
      if(replacement){replacement.value=replacementValue;replacement.dataset.previousValue=replacementValue;replacement.setSelectionRange(replacementValue.length,replacementValue.length);hodlSanitizeDiceInput(replacement)}
      hodlUpdateDice();hodlQueueMasterFingerprintPreview(0)
    }});
    hodlBindKeyFields();return
  }
  if(Ne==="hex"){
    let binary=hodlEntropyFormat==="bin",inputId=binary?"bin":"hex",entropyCharacters=binary?["0","1"]:(hodlPadShuffle?hodlShuffle([..."0123456789ABCDEF"]):[..."0123456789ABCDEF"]),entropyPad=`<div class="dice-input-pad dplus entropy-keypad${binary?" binary-keypad":""}" role="group" aria-label="${binary?"Binary":"Hexadecimal"} keypad">${entropyCharacters.map(character=>`<button type="button"${binary?' class="coin-button"':""} data-entropy-digit="${character}" aria-label="${binary?character==="0"?"Enter Heads as binary 0":"Enter Tails as binary 1":`Enter hexadecimal ${character}`}">${binary?character==="0"?"Heads (0)":"Tails (1)":character}</button>`).join("")}</div>`;
    at.innerHTML=`
      <p class="label">Entropy format</p>
      <div class="choice-grid">
      <label class="choice"><input type="radio" name="entropy-format" value="hex" ${binary?"":"checked"} />
        <span><strong>Hexadecimal</strong><span class="desc">Use characters 0–9 and a–f. Compact and easy to copy.</span></span>
      </label>
      <label class="choice"><input type="radio" name="entropy-format" value="bin" ${binary?"checked":""} />
        <span><strong>Binary (coin flips)</strong><span class="desc">Use one 0 or 1 for each coin flip.</span></span>
      </label>
      </div>
      <p class="label" id="entropy-input-label">${binary?`Binary entropy (coin flips) for a ${config.words}-word seed`:`Hexadecimal entropy for a ${config.words}-word seed`}</p>
      <p class="muted" id="entropy-input-help">${binary?`Spaces are added every 11 bits. Each complete group fills one BIP39 word; the checksum-derived final word appears at ${config.bits} bits.`:`Each hex character contributes four bits. Seed-word cards fill as enough bits arrive; the checksum-derived final word appears at exactly ${config.hexChars} characters.`} No generator — enter entropy you already created.</p>
      <div class="dice-input-shell entropy-input-shell"><pre class="dice-input-highlight" id="entropy-input-highlight" aria-hidden="true"></pre><textarea id="${inputId}" placeholder="${binary?`Exactly ${config.bits} zeros and ones`:`${config.hexChars} hex characters for a ${config.words}-word seed`}" aria-labelledby="entropy-input-label" aria-describedby="entropy-input-help entropy-meta" autocomplete="off" spellcheck="false" autocapitalize="off"></textarea></div>
      ${entropyPad}
      <label class="pad-shuffle-toggle"><input type="checkbox" id="pad-shuffle-toggle" ${hodlPadShuffle?"checked":""} /><span>Shuffle pad keys <span class="seed-autocomplete-note">(reorders the ${binary?"0/1":"hex"} keys)</span></span></label>
      <p class="muted" id="entropy-meta" aria-live="polite"></p>
      <div id="entropy-words" class="dice-word-grid" aria-label="${config.words} seed-word slots"></div>`;
    at.querySelectorAll('input[name="entropy-format"]').forEach(radio=>{radio.onchange=()=>{
      let state=hodlKeys[hodlActiveKey],previous=document.getElementById(hodlEntropyFormat);if(state&&previous)state.fields[hodlEntropyFormat]=previous.value;
      hodlEntropyFormat=radio.value==="bin"?"bin":"hex";if(state)state.entropyFormat=hodlEntropyFormat;
      hodlInvalidateLiveKeyResult();let error=document.getElementById("error");if(error)error.textContent="";
      hodlRenderKeyForm();hodlRestoreFormFields(state);hodlUpdateSeedLengthControl();hodlQueueMasterFingerprintPreview(0)
    }});
    hodlBindKeyFields();let entropyInput=document.getElementById(inputId);if(entropyInput){at.querySelectorAll("[data-entropy-digit]").forEach(button=>{button.onclick=()=>hodlInsertEntropyControl(entropyInput,button)});let shuffleToggle=at.querySelector("#pad-shuffle-toggle");if(shuffleToggle)shuffleToggle.onchange=()=>{hodlCaptureKey();let state=hodlKeys[hodlActiveKey];hodlPadShuffle=shuffleToggle.checked;if(state)state.padShuffle=hodlPadShuffle;hodlRenderKeyForm();hodlRestoreFormFields(state)}}return
  }
  if(Ne==="seed"){
    let autocompleteEnabled=Boolean(hodlKeys[hodlActiveKey]?.seedAutocomplete);
    at.innerHTML=`<p class="label">Your ${config.words}-word seed phrase</p><p class="muted" id="seed-help">Enter exactly ${config.words} English BIP39 words. You can also paste an extended key here; the selected phrase length does not apply to extended keys. With ${config.partialWords} compatible diceware words, choose the final checksum word below.</p><label class="seed-autocomplete-toggle"><input type="checkbox" id="seed-autocomplete" ${autocompleteEnabled?"checked":""} /><span>Autocomplete BIP39 words <span class="seed-autocomplete-note">(2+ letters normally; 1+ for a unique checksum word)</span></span></label><div class="dice-input-shell seed-input-shell"><pre class="dice-input-highlight" id="seed-highlight" aria-hidden="true"></pre><textarea id="seed" placeholder="Enter exactly ${config.words} BIP39 words" aria-describedby="seed-help seed-meta" autocomplete="off" spellcheck="false" autocapitalize="off"></textarea></div><p class="muted" id="seed-meta" aria-live="polite"></p><div id="last-words" class="row" style="margin-top:8px"></div><div class="dice-input-pad seed-pad" role="group" aria-label="Seed phrase keyboard">${(hodlPadShuffle?hodlShuffle([..."abcdefghijklmnopqrstuvwxyz"]):[..."abcdefghijklmnopqrstuvwxyz"]).map(character=>`<button type="button" data-vk-character="${character}" aria-label="Insert ${character}">${character}</button>`).join("")}</div><label class="pad-shuffle-toggle"><input type="checkbox" id="pad-shuffle-toggle" ${hodlPadShuffle?"checked":""} /><span>Shuffle pad keys <span class="seed-autocomplete-note">(reorders the letter keys)</span></span></label>`;
    let input=document.getElementById("seed"),update=()=>{
      let rawValue=input.value,value=rawValue.trim(),meta=W("#seed-meta"),picker=W("#last-words"),analysis=hodlRenderSeedInputState(input,config.words);
      if(hodlLooksExtendedKey(value)){let status=hodlSinglesigImportStatus(value,hodlSelectedNetwork(document.getElementById("network")));picker.innerHTML="";meta.textContent=status.message;meta.className="muted "+(status.ok?"ok":"err");return}
      let finalContext=hodlSeedFinalWordContext(rawValue,config.words),validation=hodlValidateTargetMnemonic(value,config.words),entered=analysis.tokens.length,progress=hodlSeedCountStatus(entered,config.words),remaining=Math.max(0,config.words-entered);
      if(finalContext){
        hodlRenderLastWordPicker(picker,finalContext.candidates,finalContext.selected,word=>hodlReplaceSeedFinalWord(input,finalContext,word),{forceSelect:!0,resettable:!0,targetWords:config.words,placeholder:`Choose ${config.words===18?"an":"a"} ${config.words}th word`});
        if(!finalContext.finalToken){meta.textContent=`${progress} \u00b7 choose the final checksum word \u00b7 ${finalContext.candidates.length} valid choices`;meta.className="muted ok";return}
        if(validation.ok){meta.textContent=`${progress} \u00b7 checksum valid \u00b7 ready to derive`;meta.className="muted ok";return}
        if(!finalContext.matchingCandidates.length){meta.textContent=`${progress} \u00b7 No valid checksum word starts with "${finalContext.prefix}".`;meta.className="muted err";return}
        meta.textContent=`${progress} \u00b7 ${finalContext.matchingCandidates.length} valid checksum word${finalContext.matchingCandidates.length===1?"":"s"} start${finalContext.matchingCandidates.length===1?"s":""} with "${finalContext.prefix}".`;meta.className="muted";return
      }
      picker.innerHTML="";let invalidWord=analysis.invalidWords[0];
      if(analysis.excessCount){meta.textContent=`${entered} entered \u00b7 ${config.words} required BIP39 words \u00b7 ${analysis.excessCount} extra highlighted \u00b7 remove to continue`;meta.className="muted err";return}
      if(invalidWord){meta.textContent=`${progress} \u00b7 Word ${invalidWord.index+1} (\u201c${invalidWord.word}\u201d) is not on the BIP39 English list \u00b7 correct to continue`;meta.className="muted err";return}
      if(validation.ok){meta.textContent=`${progress} \u00b7 checksum valid \u00b7 ready to derive`;meta.className="muted ok";return}
      meta.textContent=`${progress} \u00b7 ${remaining} remaining`;meta.className="muted"
    };
    let toggle=document.getElementById("seed-autocomplete");toggle.onchange=()=>{let state=hodlKeys[hodlActiveKey];if(state)state.seedAutocomplete=toggle.checked};
    input.oninput=event=>{hodlApplyFilteredInput(input,hodlFilterSeed);hodlAutocompleteSeedInput(input,event);update()};input.onscroll=()=>hodlSyncDiceHighlight(input);input.onfocus=update;input.onblur=update;let shuffleToggle=at.querySelector("#pad-shuffle-toggle");if(shuffleToggle)shuffleToggle.onchange=()=>{hodlCaptureKey();let state=hodlKeys[hodlActiveKey];hodlPadShuffle=shuffleToggle.checked;if(state)state.padShuffle=hodlPadShuffle;hodlRenderKeyForm();hodlRestoreFormFields(state)};let seedInput=input;at.querySelectorAll("[data-vk-character]").forEach(button=>{button.onclick=()=>hodlInsertEntropyControl(seedInput,button)});hodlBindKeyFields();update();return
  }
  at.innerHTML=`
    <p class="label">Private key format</p>
    <div class="choice-grid three-up">
    <label class="choice"><input type="radio" name="kk" value="wif-or-hex" checked /><span><strong>WIF / hex</strong><span class="desc">Normal Bitcoin Core private key.</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="minikey" /><span><strong>Mini key</strong><span class="desc">Casascius-style short key.</span></span></label>
    <label class="choice"><input type="radio" name="kk" value="brain" /><span><strong>Brain wallet</strong><span class="desc">Unsafe. Use only to recover an old passphrase wallet.</span></span></label>
    </div>
    <p class="label" id="private-key-input-label">Private key or recovery passphrase</p>
    <p class="muted" id="private-key-input-help">Enter the value matching the selected format. Brain wallets are for recovery only.</p>
    <textarea id="key" placeholder="K… / L… / 5… / 64-character hex / mini key" aria-labelledby="private-key-input-label" aria-describedby="private-key-input-help"></textarea>
    <div class="dice-input-pad key-pad" role="group" aria-label="Private key keyboard">${(hodlPadShuffle?hodlShuffle([..."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]):[..."123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"]).map(character=>`<button type="button" data-vk-character="${character}" aria-label="Insert ${character}">${character}</button>`).join("")}<button type="button" class="pad-wide" data-vk-character="0" aria-label="Insert 0">0 (hex only)</button></div>
    <label class="pad-shuffle-toggle"><input type="checkbox" id="pad-shuffle-toggle" ${hodlPadShuffle?"checked":""} /><span>Shuffle pad keys <span class="seed-autocomplete-note">(reorders the character keys)</span></span></label>`;
  let keyInput=document.getElementById("key");at.querySelectorAll("[data-vk-character]").forEach(button=>{button.onclick=()=>hodlInsertEntropyControl(keyInput,button)});let shuffleToggle=at.querySelector("#pad-shuffle-toggle");if(shuffleToggle)shuffleToggle.onchange=()=>{hodlCaptureKey();let state=hodlKeys[hodlActiveKey];hodlPadShuffle=shuffleToggle.checked;if(state)state.padShuffle=hodlPadShuffle;hodlRenderKeyForm();hodlRestoreFormFields(state)};hodlBindKeyFields()
}
function hodlUpdateDice(){
  let input=document.getElementById("dice");if(!input)return;let wordsBox=document.getElementById("dice-words"),picker=document.getElementById("last-words"),config=hodlSeedConfig(),inputState=hodlRenderDiceInputState(input),invalidStatus=inputState.invalidCount?` \u00b7 ${inputState.invalidCount} invalid input${inputState.invalidCount===1?"":"s"} highlighted`:"";if(ge!=="bitbox"&&inputState.coinDerivedCount)invalidStatus+=` \u00b7 coin-button digits are BitBox-only`;
  if(ge==="dplus"){
    let result=inputState.dplus||hodlDPlusRolls(input.value,config.words),status="",selectingFinal=result.waiting==="last-word",d16Range=hodlDPlusNumberedD16?"1–9 or A–G":"0–9 or A–F";
    if(ft&&(!selectingFinal||!result.candidates.includes(ft))){ft="";let state=hodlKeys[hodlActiveKey];if(state)state.dplusLastWord=""}
    let selectedFinal=selectingFinal?ft:"",complete=result.complete||Boolean(selectedFinal);
    if(result.waiting==="d8")status=`${result.completedGroups} of ${config.partialWords} groups entered \u00b7 word ${result.activeGroupIndex+1} \u00b7 D8 roll (1\u20138)`;
    else if(result.waiting==="d16-first")status=`${result.completedGroups} of ${config.partialWords} groups entered \u00b7 word ${result.activeGroupIndex+1} \u00b7 first D16 roll (${d16Range})`;
    else if(result.waiting==="d16-second")status=`${result.completedGroups} of ${config.partialWords} groups entered \u00b7 word ${result.activeGroupIndex+1} \u00b7 second D16 roll (${d16Range})`;
    else if(result.waiting==="correction"){
      let invalid=result.firstInvalid,position=invalid?.final?"the final D8 checksum roll":`word ${(invalid?.groupIndex??0)+1}'s ${invalid?.position===0?"D8":invalid?.position===1?"first D16":"second D16"} roll`;
      status=`${result.completedGroups} of ${config.partialWords} groups entered \u00b7 correct ${result.invalidRequiredCount} highlighted invalid face${result.invalidRequiredCount===1?"":"s"}, starting with ${position}`
    }
    else if(selectingFinal)status=selectedFinal?`${config.words} of ${config.words} seed words \u00b7 checksum valid \u00b7 ready to derive`:`${config.partialWords} of ${config.partialWords} word rolls complete \u00b7 choose the final checksum word`;
    else if(result.waiting==="checksum-d8")status=`${config.partialWords} of ${config.partialWords} word rolls complete \u00b7 final D8 checksum roll (1\u20138)`;
    else status=`${config.words} of ${config.words} seed words \u00b7 checksum valid \u00b7 ready to derive`;
    if(result.extraAfter)status+=` \u00b7 ${result.extraAfter} extra input${result.extraAfter===1?"":"s"} ignored`;
    let displayWords=result.wordSlots.slice();if(result.finalWord)displayWords.push(result.finalWord);else if(selectedFinal)displayWords.push(selectedFinal);hodlRenderDiceWordGrid(wordsBox,displayWords,config.words,!1);
    hodlRenderLastWordPicker(picker,selectingFinal?result.candidates:[],selectedFinal,word=>{ft=word;let state=hodlKeys[hodlActiveKey];if(state)state.dplusLastWord=ft;hodlUpdateDice()},{forceSelect:!0,resettable:!0,targetWords:config.words,placeholder:`Choose ${config.words===18?"an":"a"} ${config.words}th word`});
    let meta=W("#dice-meta");meta.textContent=status+invalidStatus;meta.className="muted"+(complete&&!result.invalidCount?" ok":result.invalidCount?" err":"");hodlQueueMasterFingerprintPreview();return
  }
  if(ge==="bitbox"){
    let result=hodlBitBoxRolls(input.value,config.words),status=result.waiting==="last-word"?`${result.words.length} words \u00b7 choose the final checksum word`:result.waiting==="coin"?`Word ${result.words.length+1} of ${result.neededPartial} \u00b7 coin / 6th die`:`Word ${result.words.length+1} of ${result.neededPartial} \u00b7 die ${result.diceInWord+1} of 5 (faces 1\u20134)`;if(result.extraAfter)status+=` \u00b7 ${result.extraAfter} extra input${result.extraAfter===1?"":"s"} ignored`;
    let last=result.waiting==="last-word"?hodlTargetLastWords(result.words.join(" "),config.words):null;if(last&&!last.error&&!last.candidates.includes(ft))ft="";
    if(!last||last.error)ft="";let displayWords=result.words.slice();if(result.waiting==="last-word"&&last&&!last.error&&ft)displayWords.push(ft);
    W("#dice-meta").textContent=status+invalidStatus;hodlRenderDiceWordGrid(wordsBox,displayWords,config.words,!1);
    hodlRenderLastWordPicker(picker,last&&!last.error?last.candidates:[],ft,word=>{ft=word;let state=hodlKeys[hodlActiveKey];if(state)state.lastWord=ft;hodlUpdateDice()},{forceSelect:!0,resettable:!0,targetWords:config.words,placeholder:`Choose ${config.words===18?"an":"a"} ${config.words}th word`});hodlQueueMasterFingerprintPreview();return
  }
  if(picker)picker.innerHTML="";let rolls=inputState.acceptedRolls,words=hodlDicePreviewWords(input.value,ge,config.words);
  let missing=Math.max(0,config.hashRolls-rolls.length),provisional=rolls.length>0&&missing>0,extra=Math.max(0,rolls.length-config.hashRolls),methodLabel=ge==="coleman"?"Hashed rolls / Dice [1-6]":"Hashed rolls / Base 10 [0-9]";
  hodlRenderDiceWordGrid(wordsBox,words,config.words,provisional);
  W("#dice-meta").textContent=(!rolls.length?`0 of ${config.hashRolls} recommended rolls \u00b7 0.0 bits estimated \u00b7 ${methodLabel}`:missing?`${rolls.length} of ${config.hashRolls} recommended rolls \u00b7 ${kr(rolls.length).toFixed(1)} bits estimated \u00b7 seed available for testing \u00b7 ${missing} more recommended`:`${rolls.length} roll${rolls.length===1?"":"s"} \u00b7 ${kr(rolls.length).toFixed(1)} bits estimated \u00b7 ready to derive${extra?` \u00b7 all ${extra} extra roll${extra===1?" is":"s are"} included`:""}`)+invalidStatus;
  hodlQueueMasterFingerprintPreview()
}
function hodlBindKeyFields(){
  let dice=document.getElementById("dice");if(dice){dice.setAttribute("inputmode",ge==="dplus"?"text":"numeric");dice.setAttribute("autocapitalize",ge==="dplus"?"characters":"off");dice.setAttribute("autocomplete","off");dice.setAttribute("spellcheck","false");dice.onbeforeinput=event=>{if(ge==="dplus")hodlHandleGroupedSeparatorDelete(dice,event);else hodlRememberDiceBeforeInput(dice,event)}}
  let hex=document.getElementById("hex");if(hex){hex.setAttribute("spellcheck","false");hex.oninput=()=>{hodlApplyFilteredInput(hex,hodlFilterHex);hodlUpdateEntropyInput(hex,"hex")};hex.onscroll=()=>hodlSyncDiceHighlight(hex);hex.oninput()}
  let binary=document.getElementById("bin");if(binary){binary.setAttribute("inputmode","numeric");binary.setAttribute("spellcheck","false");binary.onbeforeinput=event=>hodlHandleBinarySeparatorDelete(binary,event);binary.oninput=()=>{hodlFormatBinaryInput(binary);hodlUpdateEntropyInput(binary,"bin")};binary.onscroll=()=>hodlSyncDiceHighlight(binary);binary.oninput()}
  let key=document.getElementById("key");if(key){let apply=()=>{let kind=document.querySelector("input[name=kk]:checked")?.value||"wif-or-hex";if(kind!=="brain")key.value=hodlFilterKey(key.value,kind);let value=key.value.trim();if(!value){hodlHint(key,!0,"");return}if(kind==="brain"){hodlHint(key,!1,"Brain wallets are unsafe. Recovery only.");return}if(kind==="minikey"){try{Ns(value);hodlHint(key,!0,"Mini key checksum looks valid")}catch(error){hodlHint(key,!1,error.message||"Not a valid mini key")}return}if(/^[0-9a-fA-F]{64}$/.test(value)){hodlHint(key,!0,"64-character hex private key");return}try{let decoded=Ls(value),network=hodlSelectedNetwork(document.getElementById("network"));if(decoded.network!==network)throw new Error(`This WIF is for ${decoded.network}; Network is set to ${network}.`);hodlHint(key,!0,`${network} WIF private key checksum looks valid`)}catch(error){hodlHint(key,!1,error.message||"Not a valid WIF key or 64-character hex")}};key.oninput=apply;document.querySelectorAll("input[name=kk]").forEach(radio=>radio.addEventListener("change",apply))}
}
function hodlSelectedEntropy(targetWords=Pt){
  let format=hodlEntropyFormat==="bin"?"bin":"hex",value=document.getElementById(format)?.value.trim()||"";
  return format==="bin"?hodlBinaryEntropy(value,targetWords):hodlHexEntropy(value,targetWords)
}
function hodlPrivateKeyInputIsValid(){
  let input=document.getElementById("key"),value=input?.value.trim()||"";if(!value)return!1;
  let kind=document.querySelector("input[name=kk]:checked")?.value||"wif-or-hex";
  try{
    if(kind==="brain")return!0;
    if(kind==="minikey"){hf(Ns(value));return!0}
    let compact=value.replace(/\s/g,"").replace(/^0x/i,"");
    if(/^[0-9a-fA-F]{64}$/.test(compact)){hf(M.decode(compact.toLowerCase()));return!0}
    let decoded=Ls(value);if(decoded.network!==hodlSelectedNetwork(document.getElementById("network")))return!1;hf(decoded.priv);return!0
  }catch{return!1}
}
function hodlCanDeriveCurrentKey(){
  try{
    if(Ne!=="key")hodlReadAccount();
    if(Ne==="dice"){
      let input=document.getElementById("dice");if(!input)return!1;
      let analysis=hodlAnalyzeDiceInput(input.value,ge,Pt);if(analysis.invalidCount||analysis.coinDerivedCount)return!1;
      if(ge==="dplus"){
        let parsed=analysis.dplus||hodlDPlusRolls(input.value,Pt),finalWord=Pt===24?parsed.finalWord:ft;
        if(Pt===24){if(!parsed.complete)return!1}
        else if(!parsed.allRolledValid||parsed.waiting!=="last-word"||!parsed.candidates.includes(finalWord))return!1;
        return hodlValidateTargetMnemonic([...parsed.wordSlots,finalWord].join(" "),Pt).ok
      }
      if(ge==="bitbox"){
        let parsed=hodlBitBoxRolls(input.value,Pt);if(parsed.leftover||parsed.extraAfter||parsed.waiting!=="last-word"||!ft)return!1;
        let possible=hodlTargetLastWords(parsed.words.join(" "),Pt);if(!possible?.candidates.includes(ft))return!1;
        return hodlValidateTargetMnemonic([...parsed.words,ft].join(" "),Pt).ok
      }
      return hodlDiceEntropy(input.value,ge,Pt).ok
    }
    if(Ne==="hex")return hodlSelectedEntropy().ok;
    if(Ne==="seed"){
      let value=document.getElementById("seed")?.value.trim()||"";if(!value)return!1;
      if(hodlLooksExtendedKey(value))return hodlUsableSinglesigImport(value,hodlSelectedNetwork(document.getElementById("network")));
      return hodlValidateTargetMnemonic(value,Pt).ok
    }
    return hodlPrivateKeyInputIsValid()
  }catch{return!1}
}
function hodlSyncDeriveButton(){
  let button=document.getElementById("go");if(!button)return;
  button.disabled=!hodlCanDeriveCurrentKey();button.setAttribute("aria-disabled",String(button.disabled))
}
var hodlMasterFingerprintTimer=0,hodlMasterFingerprintRevision=0;
function hodlFingerprintMnemonic(){
  try{
    if(Ne==="dice"){
      let input=document.getElementById("dice");if(!input)return null;
      if(ge==="dplus"){
        let parsed=hodlDPlusRolls(input.value,Pt),finalWord=Pt===24?parsed.finalWord:ft;
        if(!parsed.allRolledValid||parsed.invalidRequiredCount||(Pt===24?!parsed.complete:parsed.waiting!=="last-word"||!parsed.candidates.includes(finalWord)))return null;
        let validation=hodlValidateTargetMnemonic([...parsed.wordSlots,finalWord].join(" "),Pt);return validation.ok?validation.words.join(" "):null
      }
      if(ge==="bitbox"){
        let parsed=hodlBitBoxRolls(input.value,Pt);if(parsed.leftover||parsed.waiting!=="last-word"||!ft)return null;
        let possible=hodlTargetLastWords(parsed.words.join(" "),Pt);if(!possible?.candidates.includes(ft))return null;
        let validation=hodlValidateTargetMnemonic([...parsed.words,ft].join(" "),Pt);return validation.ok?validation.words.join(" "):null
      }
      if(hodlAnalyzeDiceInput(input.value,ge,Pt).coinDerivedCount)return null;
      let entropy=hodlDiceEntropy(input.value,ge,Pt);return entropy.ok?_n(entropy.bytes):null
    }
    if(Ne==="hex"){
      let entropy=hodlSelectedEntropy();return entropy.ok?_n(entropy.bytes):null
    }
    if(Ne==="seed"){
      let value=document.getElementById("seed")?.value.trim()||"";if(!value||hodlLooksExtendedKey(value))return null;
      let validation=hodlValidateTargetMnemonic(value,Pt);return validation.ok?validation.words.join(" "):null
    }
  }catch{}
  return null
}
function hodlMasterFingerprint(mnemonic,passphrase=""){
  let seed=wi(mnemonic,passphrase);try{return Us(Gt.fromMasterSeed(seed).fingerprint)}finally{seed.fill(0)}
}
function hodlSetMasterFingerprintCard(card,valueNode,value){
  let available=typeof value==="string"&&value.length>0,label=card.querySelector(".master-fingerprint-label")?.textContent.trim()||"Master Fingerprint";valueNode.textContent=available?value:"";card.classList.toggle("is-disabled",!available);card.dataset.state=available?"ready":"unavailable";card.setAttribute("aria-label",available?`${label}: ${value}`:`${label} unavailable`);return available
}
function hodlRenderMasterFingerprintPreview(revision=hodlMasterFingerprintRevision){
  if(revision!==hodlMasterFingerprintRevision)return;
  let preview=document.getElementById("master-fingerprint-preview"),baseCard=document.getElementById("base-master-fingerprint-card"),base=document.getElementById("base-master-fingerprint"),arrow=document.getElementById("master-fingerprint-arrow"),derivedCard=document.getElementById("passphrase-master-fingerprint-card"),derived=document.getElementById("passphrase-master-fingerprint"),pass=document.getElementById("pass");
  if(!preview||!baseCard||!base||!arrow||!derivedCard||!derived||!pass)return;
  if(Ne==="key"){preview.hidden=!0;return}
  preview.hidden=!1;arrow.hidden=!1;derivedCard.hidden=!1;
  let clear=()=>{hodlSetMasterFingerprintCard(baseCard,base,"");hodlSetMasterFingerprintCard(derivedCard,derived,"");arrow.classList.add("is-disabled")};
  let mnemonic=hodlFingerprintMnemonic();if(!mnemonic){clear();return}
  try{hodlSetMasterFingerprintCard(baseCard,base,hodlMasterFingerprint(mnemonic))}catch{clear();return}
  let value="";if(pass.value.length>0)try{value=hodlMasterFingerprint(mnemonic,pass.value)}catch{}
  let available=hodlSetMasterFingerprintCard(derivedCard,derived,value);arrow.classList.toggle("is-disabled",!available)
}
function hodlQueueMasterFingerprintPreview(delay=90){
  let revision=++hodlMasterFingerprintRevision;clearTimeout(hodlMasterFingerprintTimer);
  if(delay<=0){hodlRenderMasterFingerprintPreview(revision);return}
  hodlMasterFingerprintTimer=setTimeout(()=>hodlRenderMasterFingerprintPreview(revision),delay)
}
function hodlInvalidateLiveKeyResult(){
  let state=hodlKeys[hodlActiveKey];if(!state)return;
  state.result=null;state.reveal=!1;re=null;Ge=!1;dr.innerHTML=""
}
function hodlInitMasterFingerprintPreview(){
  let panel=document.getElementById("calc-card"),pass=document.getElementById("pass");if(!panel||!pass)return;
  panel.addEventListener("input",event=>{
    let id=event.target?.id;if(!["pass","dice","hex","bin","seed"].includes(id))return;
    if(id==="pass"){let state=hodlKeys[hodlActiveKey];if(state)state.fields.pass=pass.value}
    hodlInvalidateLiveKeyResult();hodlQueueMasterFingerprintPreview()
  });
  panel.addEventListener("change",event=>{
    let target=event.target;if(!(target instanceof Element)||!target.matches('input[name="dm"], input[name="entropy-format"], #dplus-numbered-d16, select[aria-label^="Valid final word"]'))return;
    hodlInvalidateLiveKeyResult();hodlQueueMasterFingerprintPreview()
  });
  panel.addEventListener("click",event=>{
    let target=event.target instanceof Element?event.target.closest("#modes button, [data-seed-words], [data-d], [data-lw]"):null;if(!target)return;
    hodlInvalidateLiveKeyResult();hodlQueueMasterFingerprintPreview()
  });
  hodlQueueMasterFingerprintPreview(0)
}
function hodlCalculateKey(){
  W("#error").textContent="";
  try{
    let network=hodlSelectedNetwork(document.getElementById("network")),count=Number(document.getElementById("count").value),passphrase=document.getElementById("pass").value,scriptType=hodlSelectedScriptType(),account=Ne==="key"?0:hodlReadAccount();
    if(Ne==="dice"){
      if(ge==="dplus"){
        let parsed=hodlDPlusRolls(document.getElementById("dice").value,Pt);
        if(parsed.firstInvalid){let invalid=parsed.firstInvalid,position=invalid.final?"the final D8 checksum roll":`word ${invalid.groupIndex+1}'s ${invalid.position===0?"D8":invalid.position===1?"first D16":"second D16"} roll`;throw new Error(`Correct the highlighted invalid face in ${position}. Each D++ word keeps its original three-character group.`)}
        if(parsed.waiting==="d8")throw new Error(`Complete word ${parsed.activeGroupIndex+1}: roll the D8, then both D16 dice.`);
        if(parsed.waiting==="d16-first")throw new Error(`Complete word ${parsed.activeGroupIndex+1}: enter the first D16 roll.`);
        if(parsed.waiting==="d16-second")throw new Error(`Complete word ${parsed.activeGroupIndex+1}: enter the second D16 roll.`);
        if(parsed.waiting==="checksum-d8")throw new Error("Roll the final D8 to select one of the eight checksum-valid 24th words.");
        let finalWord=Pt===24?parsed.finalWord:ft;if(Pt!==24&&(!finalWord||!parsed.candidates.includes(finalWord)))throw new Error(`Choose one of the ${hodlSeedConfig().candidates} valid final checksum words before deriving the wallet.`);
        if(Pt===24&&!parsed.complete)throw new Error("Complete all D++ rolls before deriving the wallet.");
        let phrase=[...parsed.wordSlots,finalWord].join(" "),validation=hodlValidateTargetMnemonic(phrase,Pt);if(!validation.ok)throw new Error(validation.error);let notes=parsed.notes.slice();if(Pt!==24)notes.push(`Selected checksum-valid final word: ${finalWord}.`);re=ar(phrase,passphrase,network,count,{notes,warnings:parsed.warnings},account)
      }else if(ge==="bitbox"){
        let parsed=hodlBitBoxRolls(document.getElementById("dice").value,Pt);if(parsed.leftover)throw new Error(`Invalid characters: ${parsed.leftover}`);if(parsed.waiting!=="last-word")throw new Error(`Need ${parsed.neededPartial} lookup-table words for a ${Pt}-word seed. You have ${parsed.words.length}.`);
        let possible=hodlTargetLastWords(parsed.words.join(" "),Pt);if(!ft||!possible?.candidates.includes(ft))throw new Error(`Choose one of the ${hodlSeedConfig().candidates} valid final checksum words before deriving the wallet.`);
        let phrase=[...parsed.words,ft].join(" "),validation=hodlValidateTargetMnemonic(phrase,Pt);if(!validation.ok)throw new Error(validation.error);re=ar(phrase,passphrase,network,count,{notes:parsed.notes,warnings:parsed.warnings},account)
      }else{let diceValue=document.getElementById("dice").value;if(hodlAnalyzeDiceInput(diceValue,ge,Pt).coinDerivedCount)throw new Error("Coin-button digits are entropy-equivalent only in BitBox mode. Clear them and enter fair die rolls for this conversion method.");let entropy=hodlDiceEntropy(diceValue,ge,Pt);if(!entropy.ok)throw new Error(entropy.error);re=on(entropy,passphrase,network,count,account)}
    }else if(Ne==="hex"){
      let entropy=hodlSelectedEntropy();if(!entropy.ok)throw new Error(entropy.error);re=on(entropy,passphrase,network,count,account)
    }else if(Ne==="seed"){
      let value=document.getElementById("seed").value.trim();if(hodlLooksExtendedKey(value))re=Po(value,network,count,account);else{let validation=hodlValidateTargetMnemonic(value,Pt);if(!validation.ok)throw new Error(validation.error);re=ar(validation.words.join(" "),passphrase,network,count,undefined,account)}
    }else{let kind=document.querySelector("input[name=kk]:checked")?.value||"wif-or-hex";re=Io(document.getElementById("key").value,network,kind)}
    if(re?.network!==network)throw new Error(`The supplied key is for ${re.network}, but Network is set to ${network}.`);
    Ge=!1;hodlSetSelectedScriptType(scriptType);tc();hodlFocusWalletResult();hodlCaptureKey()
  }catch(error){re=null;W("#error").textContent=error instanceof Error?error.message:"Could not derive wallet";dr.innerHTML="";hodlCaptureKey()}
}
function hodlFilterHex(e){return e.replace(/[^0-9a-fA-F\s]/g,"")}
function hodlFilterBin(e){return e.replace(/[^01\s]/g,"")}
function hodlFilterSeed(e){return e.replace(/[^a-zA-Z0-9\s]/g,"")}
function hodlFilterKey(e,t){return t==="brain"?e:e.replace(/[^0-9A-Za-z\s]/g,"")}
function hodlFilterXpub(e){return String(e??"").replace(/[^A-Za-z0-9[\]/']/g,"")}
function hodlNormalizeOriginPath(path){return String(path??"").trim().replace(/^m\//i,"").replace(/'/g,"h").replace(/H/g,"h")}
function hodlParseKeyOrigin(raw){
  let input=String(raw??"").trim();
  let match=input.match(/^\[([0-9a-fA-F]{8})\/([0-9A-Za-z/']+)\](.+)$/);
  if(!match)return{origin:null,key:input};
  let fingerprint=match[1].toLowerCase(),path=hodlNormalizeOriginPath(match[2]),key=String(match[3]||"").trim().replace(/\/(?:<\d+(?:;\d+)*>|\d+)\/\*$/,"");
  if(fingerprint==="00000000")throw new Error("Key origin fingerprint 00000000 is not a real master fingerprint.");
  if(!/^(?:\d+h?)(?:\/\d+h?)*$/.test(path))throw new Error("Key origin path must look like 48h/0h/0h/2h.");
  if(!key)throw new Error("Key origin is missing the extended public key.");
  return{origin:{fingerprint,path},key}
}
function hodlOriginPathIndexes(path){
  return hodlNormalizeOriginPath(path).split("/").filter(Boolean).map(step=>{
    let hardened=step.endsWith("h"),index=Number(hardened?step.slice(0,-1):step);
    if(!Number.isInteger(index)||index<0||index>0x7fffffff)throw new Error("Key origin path has an invalid index.");
    return hardened?0x80000000+index:index
  })
}
function hodlOriginMatchesParsedKey(origin,parsed){
  let indexes=hodlOriginPathIndexes(origin.path);
  if(indexes.length!==parsed.depth)return`Key origin path has ${indexes.length} steps, but this extended key is depth ${parsed.depth}.`;
  if(indexes[indexes.length-1]!==parsed.childNumber)return"Key origin path does not end at this extended key.";
  return""
}
function hodlMultisigDerivationStandard(origin){
  let steps=hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean);
  if(steps[0]==="45h")return"bip45";
  if(steps[0]==="87h")return"bip87";
  if(steps[0]==="48h")return"bip48";
  return null
}
function hodlOriginScriptError(origin,kind,network,legacyStandard="bip45"){
  let steps=hodlNormalizeOriginPath(origin.path).split("/");
  if(kind==="p2wsh"||kind==="p2sh-p2wsh"){
    if(steps[0]!=="48h")return"This script type's origin must start at 48h.";
    let coin=network==="testnet"?"1h":"0h";
    if(steps[1]!==coin)return`This ${network} origin should use ${coin} as the coin type.`;
    if(steps.length!==4)return"BIP48 origin must be 48h/coin/account/script.";
    if(!/^\d+h$/.test(steps[2]))return"BIP48 account index must be hardened.";
    let last=kind==="p2wsh"?"2h":"1h";
    if(steps[3]!==last)return`This script type's origin must end in ${last}.`;
    return""
  }
  if(legacyStandard==="bip87"){
    if(steps[0]!=="87h")return"Legacy BIP87 origin must start at 87h.";
    let coin=network==="testnet"?"1h":"0h";
    if(steps[1]!==coin)return`This ${network} BIP87 origin should use ${coin} as the coin type.`;
    if(steps.length!==3)return"BIP87 origin must be 87h/coin/account.";
    if(!/^\d+h$/.test(steps[2]))return"BIP87 account index must be hardened.";
    return""
  }
  if(steps.length!==1||steps[0]!=="45h")return"Legacy P2SH requires the BIP45 purpose origin 45h.";
  return""
}
function hodlMultisigAccountNumber(origin,kind){
  let steps=hodlNormalizeOriginPath(origin?.path).split("/");
  if(kind==="p2sh"&&steps[0]==="45h")return null;
  let standard=kind==="p2sh"?"BIP87":"BIP48",match=steps[2]?.match(/^(\d+)h$/);
  if(!match)throw new Error(`${standard} account index must be hardened.`);
  let account=Number(match[1]);
  if(!Number.isSafeInteger(account)||account<0||account>0x7fffffff)throw new Error(`${standard} account index is out of range.`);
  return account
}
function hodlSummarizeMultisigAccounts(accountNumbers){
  let accounts=[...new Set(accountNumbers.filter(account=>Number.isSafeInteger(account)&&account>=0&&account<=0x7fffffff))].sort((a,b)=>a-b);
  let mixed=accounts.length>1;return{account:accounts.length===1?accounts[0]:null,accounts,consistent:!mixed,mixed}
}
function hodlMultisigAccountWarning(summary){
  return summary.consistent?"":`Co-signer account numbers do not match (${summary.accounts.join(", ")}). The Account field is shown as Mixed.`
}
function hodlMultisigOriginScriptKind(origin){
  let steps=hodlNormalizeOriginPath(origin?.path).split("/").filter(Boolean);
  if(steps.length===1&&steps[0]==="45h")return"p2sh";
  if(steps[0]!=="48h"||steps.length!==4)return null;
  if(steps[3]==="1h")return"p2sh-p2wsh";
  if(steps[3]==="2h")return"p2wsh";
  return null
}
function hodlMultisigScriptEvidence(parsed){
  let prefixKind=parsed?.scope==="multisig"?(parsed.family==="y"?"p2sh-p2wsh":parsed.family==="z"?"p2wsh":null):null;
  return{prefixKind,originKind:hodlMultisigOriginScriptKind(parsed?.origin),standard:hodlMultisigDerivationStandard(parsed?.origin)}
}
function hodlSummarizeMultisigScriptKinds(kinds){
  let supported=["p2sh","p2sh-p2wsh","p2wsh"],unique=[...new Set((kinds||[]).filter(kind=>supported.includes(kind)))];
  return{kind:unique.length>1?"mixed":unique[0]||null,kinds:unique,mixed:unique.length>1}
}
function hodlParseMultisigCosigner(raw){
  let parsedOrigin=hodlParseKeyOrigin(raw),parsed=uf(parsedOrigin.key);
  parsed.origin=parsedOrigin.origin;
  return parsed
}
function hodlDetectMsigScriptSummary(values=hodlReadMsigXpubs()){
  let kinds=[],legacyStandards=[];
  for(let raw of values){
    if(!String(raw??"").trim())continue;
    try{let evidence=hodlMultisigScriptEvidence(hodlParseMultisigCosigner(raw));if(evidence.prefixKind)kinds.push(evidence.prefixKind);if(evidence.originKind)kinds.push(evidence.originKind);if(evidence.standard==="bip45"||evidence.standard==="bip87")legacyStandards.push(evidence.standard)}catch{}
  }
  let summary=hodlSummarizeMultisigScriptKinds(kinds),standards=[...new Set(legacyStandards)],legacyScriptConflict=standards.includes("bip87")&&summary.kinds.some(kind=>kind!=="p2sh");
  return{...summary,legacyStandard:standards.length===1?standards[0]:null,legacyStandards:standards,legacyMixed:standards.length>1,legacyScriptConflict}
}
function hodlMultisigScriptLabel(kind){return kind==="p2sh"?"Legacy":kind==="p2sh-p2wsh"?"Nested SegWit":kind==="p2wsh"?"Native SegWit":"Unknown"}
function hodlSelectedLegacyMultisigStandard(){return document.getElementById("msig-legacy-bip87")?.checked?"bip87":"bip45"}
function hodlUpdateMsigLegacyControls(){
  let checkbox=document.getElementById("msig-legacy-bip87"),toggle=document.getElementById("msig-legacy-account-toggle"),option=document.querySelector('#msig-script-type option[value="p2sh"]'),legacy=hodlScriptKind()==="p2sh";
  if(toggle)toggle.hidden=!legacy;
  if(option)option.textContent=checkbox?.checked?"Legacy · BIP87":"Legacy · BIP45"
}
function hodlMultisigKeyPlaceholder(kind,network,legacyStandard="bip45"){
  let testnet=network==="testnet",coin=testnet?"1h":"0h";
  if(kind==="p2sh"&&legacyStandard==="bip87")return`[fingerprint/87h/${coin}/0h]${testnet?"tpub":"xpub"}…`;
  if(kind==="p2sh")return`[fingerprint/45h]${testnet?"tpub":"xpub"}…`;
  if(kind==="p2sh-p2wsh")return`[fingerprint/48h/${coin}/0h/1h]${testnet?"Upub":"Ypub"}…`;
  if(kind==="p2wsh")return`[fingerprint/48h/${coin}/0h/2h]${testnet?"Vpub":"Zpub"}…`;
  return"Use matching multisig extended public keys"
}
function hodlUpdateMsigKeyPlaceholders(){
  let kind=hodlScriptKind(),network=hodlSelectedNetwork(document.getElementById("msig-network")),placeholder=hodlMultisigKeyPlaceholder(kind,network,hodlSelectedLegacyMultisigStandard());
  document.querySelectorAll("#msig-keys textarea").forEach(textarea=>{textarea.placeholder=placeholder})
}
function hodlSyncMsigDeriveButton(){
  let button=document.getElementById("msig-go");if(!button)return;
  let ready=!1,reason="";try{hodlValidatedMsigInputs();ready=!0}catch(error){reason=error.message||"Complete every multisig field."}
  button.disabled=!ready;button.setAttribute("aria-disabled",String(!ready));button.title=ready?"":reason
}
function hodlUpdateMsigScriptDetection(){
  let select=document.getElementById("msig-script-type");if(!select)return hodlSummarizeMultisigScriptKinds([]);
  let summary=hodlDetectMsigScriptSummary(),desired=summary.mixed||summary.legacyMixed||summary.legacyScriptConflict?"mixed":summary.kind,checkbox=document.getElementById("msig-legacy-bip87");
  if(desired==="mixed"){
    if(select.value!=="mixed")select.dataset.lastConcrete=select.value;
    hodlSyncSelect(select,"mixed")
  }else if(desired){
    select.dataset.lastConcrete=desired;hodlSyncSelect(select,desired)
  }else if(select.value==="mixed"){
    hodlSyncSelect(select,select.dataset.lastConcrete||"p2wsh")
  }else select.dataset.lastConcrete=select.value;
  if((desired==="p2sh"||select.value==="p2sh")&&summary.legacyStandard&&checkbox)checkbox.checked=summary.legacyStandard==="bip87";
  hodlUpdateMsigLegacyControls();
  let warning=document.getElementById("msig-script-warning"),labels=summary.kinds.map(hodlMultisigScriptLabel),bip87NeedsScript=summary.legacyStandard==="bip87"&&!summary.kind&&select.value!=="p2sh",message=summary.legacyMixed?"Legacy co-signer exports mix BIP45 and BIP87. Choose one derivation standard and export every key from it.":summary.legacyScriptConflict?"BIP87 account keys are script-agnostic, but this app uses them only with Legacy P2SH. They cannot be combined here with BIP48 keys.":summary.mixed?`Co-signer exports indicate different script types (${labels.join(" and ")}). A Mixed selection does not define one multisig output policy; export every key for the same script type before deriving.`:bip87NeedsScript?"BIP87 keys do not encode a script type. Select Legacy P2SH to use this standardized account key here.":"";
  if(warning){warning.textContent=message;warning.hidden=!message}
  hodlUpdateMsigKeyPlaceholders();hodlSyncMsigDeriveButton();return summary
}
function hodlMultisigKeyToken(parsed,network){
  let canonical=hodlSerializeExtendedKey(parsed.node.publicExtendedKey,network,"x",!1);
  if(!parsed.origin)throw new Error("Paste the complete key origin and extended public key so a signer can recognize it.");
  return`[${parsed.origin.fingerprint}/${parsed.origin.path}]${canonical}`
}
function hodlHint(el,ok,msg){if(!el)return;el.classList.toggle("bad",!ok&&!!msg);let anchor=el.closest(".dice-input-shell")||el,h=anchor.nextElementSibling;if(!h||!h.classList.contains("hint")){h=document.createElement("p");h.className="hint";anchor.insertAdjacentElement("afterend",h)}h.textContent=msg||"";h.className="hint "+(ok?"ok":msg?"bad":"")}
function hodlBindFields(){let d=document.getElementById("dice");if(d){d.setAttribute("inputmode","numeric");d.setAttribute("autocomplete","off");d.setAttribute("spellcheck","false")}
let hx=document.getElementById("hex");if(hx){hx.setAttribute("spellcheck","false");hx.oninput=()=>{hx.value=hodlFilterHex(hx.value);let n=hx.value.replace(/\s/g,"");let ok=!n||/^[0-9a-fA-F]+$/.test(n)&&(n.length%2===0);let msg=!n?"":n.length===32?"32 hex characters · 12-word seed":n.length===64?"64 hex characters · 24-word seed":n.length<32?"Need 32 hex characters for 12 words (or 64 for 24)":n.length%2?"Hex must be an even number of characters":ok?n.length*4+" bits":"Not hex";hodlHint(hx,ok&&(!n||n.length===32||n.length===40||n.length===48||n.length===56||n.length===64),msg)}}
let bn=document.getElementById("bin");if(bn){bn.oninput=()=>{bn.value=hodlFilterBin(bn.value);let n=bn.value.replace(/\s/g,"");hodlHint(bn,!n||n.length>=128,n&&n.length<128?"Need at least 128 coin flips":n?n.length+" bits":"")}}
let ky=document.getElementById("key");if(ky){let apply=()=>{let kind=(document.querySelector("input[name=kk]:checked")||{}).value||"wif-or-hex";if(kind!=="brain")ky.value=hodlFilterKey(ky.value,kind);let v=ky.value.trim();if(!v){hodlHint(ky,!0,"");return}if(kind==="brain"){hodlHint(ky,!1,"Brain wallets are unsafe. Recovery only.");return}if(kind==="minikey"){try{Ns(v);hodlHint(ky,!0,"Mini key checksum looks valid")}catch(err){hodlHint(ky,!1,err.message||"Not a valid mini key")}return}if(/^[0-9a-fA-F]{64}$/.test(v)){hodlHint(ky,!0,"64-character hex private key");return}try{Ls(v);hodlHint(ky,!0,"WIF private key checksum looks valid")}catch(err){hodlHint(ky,!1,"Not a WIF key or 64-character hex")}};ky.oninput=apply;document.querySelectorAll("input[name=kk]").forEach(r=>{r.addEventListener("change",apply)})}}
var hodlWorkspace="calc",hodlWorkspaceScrollFrame=0;
function hodlReadMsigXpubs(){return[...document.querySelectorAll("#msig-keys textarea")].map(ta=>ta.value)}
function hodlMergeMsigXpubs(state,values){let cached=Array.isArray(state?.fields?.xpubs)?state.fields.xpubs.slice():[];(values||hodlReadMsigXpubs()).forEach((value,index)=>{cached[index]=value});if(state)state.fields.xpubs=cached;return cached}
function hodlUpdateMsigAccount(){
  let field=document.getElementById("msig-account");if(!field)return hodlSummarizeMultisigAccounts([]);
  let kind=hodlScriptKind(),legacyStandard=hodlSelectedLegacyMultisigStandard(),help=document.getElementById("msig-account-help"),warning=document.getElementById("msig-account-warning");
  if(kind==="p2sh"&&legacyStandard==="bip45"){
    field.value="";field.placeholder="Not applicable";field.dataset.state="not-applicable";
    if(help)help.textContent="BIP45 purpose keys do not contain an account number.";
    if(warning){warning.textContent="";warning.hidden=!0}
    return hodlSummarizeMultisigAccounts([])
  }
  let accountNumbers=[];
  for(let raw of hodlReadMsigXpubs()){
    if(!raw.trim())continue;
    try{let parsed=hodlParseMultisigCosigner(raw.trim());if(parsed.origin)accountNumbers.push(hodlMultisigAccountNumber(parsed.origin,kind))}catch{}
  }
  let summary=hodlSummarizeMultisigAccounts(accountNumbers),message=hodlMultisigAccountWarning(summary);
  field.value=summary.mixed?"Mixed":summary.account==null?"":String(summary.account);field.placeholder="Derived from keys";field.dataset.state=summary.mixed?"mixed":summary.account==null?"empty":"account";
  if(help)help.textContent=summary.mixed?"Co-signer key origins use different account numbers.":summary.account==null?kind==="p2sh"?"Derived from BIP87 co-signer key origins.":"Derived from co-signer key origins.":"Derived from the co-signer account paths.";
  if(warning){warning.textContent=message;warning.hidden=!message}
  return summary
}
function hodlInvalidateMsig(){let state=hodlMsigs[hodlActiveMsig];if(state){state.result=null;state.error=""}re=null;dr.innerHTML="";let err=document.getElementById("msig-error");if(err)err.textContent="";hodlUpdateMsigAccount();hodlSyncMsigDeriveButton()}
function hodlUpdateMsigHint(){let n=Number(document.getElementById("msig-n").value||3),m=document.getElementById("msig-m").value||"2",hint=document.getElementById("msig-hint");if(hint){hint.textContent=n===1?"Spending will need this key. Receiving needs none of the private keys.":`Spending will need ${m} of these ${n} keys. Receiving needs none of the private keys.`;hint.className="hint ok"}}
var hodlMsigSliderBaseMax=9,hodlMsigSliderLimit=15;
function hodlClampMsigThreshold(value,min,max){let number=Number(value);return Math.min(max,Math.max(min,Number.isFinite(number)?Math.round(number):min))}
function hodlRenderMsigThreshold(){
  let mInput=document.getElementById("msig-m"),nInput=document.getElementById("msig-n"),slider=document.getElementById("msig-threshold-slider"),ticks=document.getElementById("msig-threshold-ticks");
  if(!mInput||!nInput||!slider||!ticks)return;
  let m=Number(mInput.value),n=Number(nInput.value),visibleMax=Math.max(hodlMsigSliderBaseMax,n),span=Math.max(1,visibleMax-1);
  slider.style.setProperty("--msig-m-position",(m-1)/span*100+"%");slider.style.setProperty("--msig-n-position",(n-1)/span*100+"%");
  slider.dataset.sliderMax=String(visibleMax);slider.dataset.overlap=String(m===n);
  let mNumber=document.getElementById("msig-m-number"),nNumber=document.getElementById("msig-n-number");
  if(mNumber){mNumber.value=String(m);mNumber.min="1";mNumber.max=String(hodlMsigSliderLimit)}if(nNumber){nNumber.value=String(n);nNumber.min="1";nNumber.max=String(hodlMsigSliderLimit)}
  mInput.setAttribute("aria-valuetext",m+" signature"+(m===1?"":"s")+" needed");nInput.setAttribute("aria-valuetext",n+" total signing key"+(n===1?"":"s"));
  let fragment=document.createDocumentFragment();for(let value=1;value<=visibleMax;value++){let tick=document.createElement("span");tick.textContent=String(value);tick.style.setProperty("--msig-tick-position",(value-1)/span*100+"%");fragment.appendChild(tick)}ticks.replaceChildren(fragment)
}
function hodlSetMsigThresholds(mValue,nValue,changed,moveOther){
  let mInput=document.getElementById("msig-m"),nInput=document.getElementById("msig-n");if(!mInput||!nInput)return{m:2,n:3};
  let n=hodlClampMsigThreshold(nValue,1,hodlMsigSliderLimit),m=hodlClampMsigThreshold(mValue,1,hodlMsigSliderLimit);
  if(moveOther){if(changed==="m")n=Math.max(n,m);else if(changed==="n")m=Math.min(m,n)}else if(changed==="n")n=Math.max(n,m);else m=Math.min(m,n);
  mInput.value=String(m);nInput.value=String(n);hodlRenderMsigThreshold();hodlUpdateMsigHint();return{m,n}
}
function hodlChangeMsigThreshold(handle,value,moveOther){
  let mInput=document.getElementById("msig-m"),nInput=document.getElementById("msig-n"),previousN=document.querySelectorAll("#msig-keys textarea").length||Number(nInput.value||3),state=hodlMsigs[hodlActiveMsig];
  let saved=state?hodlMergeMsigXpubs(state):hodlReadMsigXpubs(),next=hodlSetMsigThresholds(handle==="m"?value:mInput.value,handle==="n"?value:nInput.value,handle,moveOther);
  if(next.n!==previousN)hodlFillKeys(saved);else hodlUpdateMsigHint();hodlInvalidateMsig()
}
function hodlMsigThresholdPointerValue(clientX,rect,visibleMax){
  let ratio=Math.min(1,Math.max(0,(clientX-rect.left)/Math.max(1,rect.width)));
  return Math.round(1+ratio*(visibleMax-1))
}
function hodlBindMsigThresholdSlider(){
  let slider=document.getElementById("msig-threshold-slider"),mInput=document.getElementById("msig-m"),nInput=document.getElementById("msig-n"),mNumber=document.getElementById("msig-m-number"),nNumber=document.getElementById("msig-n-number");if(!slider||!mInput||!nInput)return;
  let drag=null,setActive=(handle,value)=>{slider.dataset.activeHandle=handle;document.getElementById("msig-"+handle)?.focus({preventScroll:!0});hodlChangeMsigThreshold(handle,value)};
  mInput.addEventListener("input",()=>hodlChangeMsigThreshold("m",mInput.value));nInput.addEventListener("input",()=>hodlChangeMsigThreshold("n",nInput.value));
  mInput.addEventListener("focus",()=>{slider.dataset.activeHandle="m"});nInput.addEventListener("focus",()=>{slider.dataset.activeHandle="n"});
  let bindNumber=(input,handle)=>{if(!input)return;let apply=commit=>{let raw=input.value.trim();if(!raw){if(commit)hodlRenderMsigThreshold();return}hodlChangeMsigThreshold(handle,raw,!0)};input.addEventListener("input",()=>apply(!1));input.addEventListener("change",()=>apply(!0));input.addEventListener("blur",()=>apply(!0));input.addEventListener("focus",()=>input.select());input.addEventListener("keydown",event=>{if(["e","E","+","-","."].includes(event.key))event.preventDefault();if(event.key==="Enter"){event.preventDefault();apply(!0);input.select()}})};
  bindNumber(mNumber,"m");bindNumber(nNumber,"n");
  slider.addEventListener("pointerdown",event=>{
    if(event.button!==0)return;event.preventDefault();let rect=slider.getBoundingClientRect(),m=Number(mInput.value),n=Number(nInput.value),visibleMax=Math.max(hodlMsigSliderBaseMax,n),point=hodlMsigThresholdPointerValue(event.clientX,rect,visibleMax),handle=m===n?null:Math.abs(point-m)<=Math.abs(point-n)?"m":"n";
    drag={pointerId:event.pointerId,startX:event.clientX,rect,visibleMax,handle};slider.setPointerCapture(event.pointerId);if(handle)setActive(handle,point)
  });
  slider.addEventListener("pointermove",event=>{
    if(!drag||event.pointerId!==drag.pointerId)return;event.preventDefault();if(!drag.handle){let delta=event.clientX-drag.startX;if(Math.abs(delta)<3)return;drag.handle=delta<0?"m":"n"}
    let value=drag.handle==="n"&&event.clientX>drag.rect.right?Math.min(hodlMsigSliderLimit,drag.visibleMax+Math.ceil((event.clientX-drag.rect.right)/28)):hodlMsigThresholdPointerValue(event.clientX,drag.rect,drag.visibleMax);
    setActive(drag.handle,value)
  });
  let finish=event=>{if(!drag||event.pointerId!==drag.pointerId)return;if(!drag.handle){slider.dataset.activeHandle="n";nInput.focus({preventScroll:!0})}drag=null};
  slider.addEventListener("pointerup",finish);slider.addEventListener("pointercancel",finish);slider.addEventListener("lostpointercapture",()=>{drag=null})
}
function hodlFillKeys(values){
  let n=Number(document.getElementById("msig-n").value||3),saved=Array.isArray(values)?values:hodlReadMsigXpubs(),box=document.getElementById("msig-keys");box.innerHTML="";
  for(let i=0;i<n;i++){
    let lab=document.createElement("label");lab.className="field";lab.textContent="Co-signer "+(i+1)+" multisig extended public key";
    let ta=document.createElement("textarea");ta.id="msig-x-"+i;ta.autocomplete="off";ta.spellcheck=false;ta.value=saved[i]||"";lab.appendChild(ta);box.appendChild(lab);
    ta.oninput=()=>{ta.value=hodlFilterXpub(ta.value);hodlUpdateMsigScriptDetection();document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);hodlInvalidateMsig()}
  }
  hodlUpdateMsigScriptDetection();box.querySelectorAll("textarea").forEach(ta=>{if(ta.value)hodlCheckXpub(ta)});hodlUpdateMsigHint();hodlUpdateMsigAccount()
}
function hodlMultisigPrefixCompatible(parsed,kind){
  if(parsed.scope==="singlesig")return parsed.family==="x";
  if(kind==="p2sh-p2wsh")return parsed.family==="y";
  if(kind==="p2wsh")return parsed.family==="z";
  return!1
}
function hodlMultisigAccountKeyError(parsed,kind,legacyStandard="bip45"){
  if(kind==="p2wsh"||kind==="p2sh-p2wsh"){
    let scriptIndex=kind==="p2wsh"?2:1,label=kind==="p2wsh"?"Native SegWit":"Nested SegWit",expected=0x80000000+scriptIndex;
    if(parsed.depth!==4)return`${label} requires a depth-4 BIP48 script-account key ending in /${scriptIndex}h; this key is depth ${parsed.depth}.`;
    if(parsed.childNumber!==expected)return`${label} requires a BIP48 script-account key whose final hardened child is ${scriptIndex}h.`;
    return""
  }
  if(legacyStandard==="bip87"){
    if(parsed.depth!==3)return`Legacy BIP87 requires a depth-3 account key at m/87h/coinh/accounth; this key is depth ${parsed.depth}.`;
    if(parsed.childNumber<0x80000000)return"A BIP87 account index must be hardened.";
    return""
  }
  if(parsed.depth!==1)return`Legacy P2SH requires the depth-1 BIP45 purpose key at m/45h; this key is depth ${parsed.depth}.`;
  if(parsed.childNumber!==0x8000002d)return"Legacy P2SH requires the hardened BIP45 purpose child at m/45h.";
  return""
}
function hodlCanonicalMultisigKey(parsed){return hodlSerializeExtendedKey(parsed.node.publicExtendedKey,parsed.network,"x",!1)}
function hodlDuplicateMultisigKey(ta,parsed){
  let canonical=hodlCanonicalMultisigKey(parsed);
  for(let other of document.querySelectorAll("#msig-keys textarea")){
    if(other===ta||!other.value.trim())continue;
    try{if(hodlCanonicalMultisigKey(hodlParseMultisigCosigner(other.value.trim()))===canonical)return!0}catch{}
  }
  return!1
}
function hodlCheckXpub(ta){let value=ta.value.trim();if(!value){hodlHint(ta,!0,"");return}try{let parsed=hodlParseMultisigCosigner(value),network=hodlSelectedNetwork(document.getElementById("msig-network")),kind=hodlScriptKind(),legacyStandard=hodlSelectedLegacyMultisigStandard();if(kind==="mixed")throw new Error("These keys do not define one compatible multisig policy. Use one script type and one Legacy derivation standard.");if(parsed.isPrivate)throw new Error("Paste an extended public key, never an extended private key.");if(parsed.network!==network)throw new Error(`${parsed.prefix} is for ${parsed.network}; the multisig is set to ${network}.`);if(!hodlMultisigPrefixCompatible(parsed,kind))throw new Error(parsed.scope==="singlesig"?"Use a generic xpub/tpub here, or a proper uppercase multisig SLIP-132 export.":`${parsed.prefix} does not match the selected multisig script type.`);let accountError=hodlMultisigAccountKeyError(parsed,kind,legacyStandard);if(accountError)throw new Error(accountError);if(!parsed.origin)throw new Error(`Paste ${hodlMultisigKeyPlaceholder(kind,network,legacyStandard)} so a signer can recognize this key.`);let originError=hodlOriginMatchesParsedKey(parsed.origin,parsed);if(originError)throw new Error(originError);let scriptOriginError=hodlOriginScriptError(parsed.origin,kind,network,legacyStandard);if(scriptOriginError)throw new Error(scriptOriginError);if(hodlDuplicateMultisigKey(ta,parsed))throw new Error("This duplicates another co-signer. Every co-signer must use a distinct extended public key.");hodlHint(ta,!0,`${parsed.prefix} origin, checksum, and derivation path look valid`)}catch(error){hodlHint(ta,!1,error.message||"Not a valid multisig extended public key")}}
function hodlResetMsigForm(){hodlSetMsigThresholds(2,3);hodlSyncSelect(document.getElementById("msig-script-type"),"p2wsh");let legacy=document.getElementById("msig-legacy-bip87");if(legacy)legacy.checked=!1;hodlUpdateMsigLegacyControls();hodlSyncSelect(document.getElementById("msig-network"),"mainnet");hodlSyncSelect(document.getElementById("msig-count"),"5");hodlFillKeys([]);document.getElementById("msig-error").textContent=""}
function hodlInitMsig(){hodlBindMsigThresholdSlider();let recheck=()=>{hodlUpdateMsigScriptDetection();hodlInvalidateMsig();document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub)},script=document.getElementById("msig-script-type"),legacy=document.getElementById("msig-legacy-bip87");script.addEventListener("change",()=>{if(script.value!=="mixed")script.dataset.lastConcrete=script.value;recheck()});if(legacy)legacy.addEventListener("change",()=>{hodlUpdateMsigLegacyControls();hodlUpdateMsigKeyPlaceholders();hodlInvalidateMsig();document.querySelectorAll("#msig-keys textarea").forEach(hodlCheckXpub);hodlSyncMsigClearButton(!0)});document.getElementById("msig-network").addEventListener("change",recheck);document.getElementById("msig-count").addEventListener("change",hodlInvalidateMsig);hodlResetMsigForm();W("#msig-go").onclick=hodlBuildMsig;W("#msig-wipe").onclick=hodlWipeActiveMsig}
function hodlCmpBytes(a,b){let n=Math.min(a.length,b.length);for(let i=0;i<n;i++)if(a[i]!==b[i])return a[i]-b[i];return a.length-b.length}
function hodlScriptKind(){return document.getElementById("msig-script-type")?.value||"p2wsh"}
function hodlMsigAddr(pubkeys,m,network,kind){let sorted=[...pubkeys].sort(hodlCmpBytes);let ms=Oe.encode({type:"ms",m,pubkeys:sorted});let net=_s(network);if(kind==="p2wsh"){let hash=tr(ms);return{address:or(net).encode({type:"wsh",hash}),scriptHex:M.encode(ms),kind}}if(kind==="p2sh-p2wsh"){let hash=tr(ms);let wshScript=Oe.encode({type:"wsh",hash});let wrapped=Jr({script:wshScript,witnessScript:ms},net);return{address:wrapped.address,scriptHex:M.encode(ms),kind}}let wrapped=Jr({script:ms},net);return{address:wrapped.address,scriptHex:M.encode(ms),kind}}
function hodlValidatedMsigInputs(){
  let network=hodlSelectedNetwork(document.getElementById("msig-network")),count=Number(document.getElementById("msig-count")?.value),n=Number(document.getElementById("msig-n")?.value),m=Number(document.getElementById("msig-m")?.value);
  if(!(m>=1&&n>=1&&m<=n&&n<=15))throw new Error("Pick how many signatures out of how many keys.");
  if(![5,10,20].includes(count))throw new Error("Choose how many receive and change addresses to derive.");
  let kind=hodlScriptKind(),legacyStandard=hodlSelectedLegacyMultisigStandard(),nodes=[],xpubs=[],keyTokens=[],accountNumbers=[];
  if(kind==="mixed")throw new Error("Co-signer keys indicate different script types. Export every key for the same multisig script type before deriving.");
  for(let index=0;index<n;index++){
    let field=document.getElementById("msig-x-"+index),raw=field?.value.trim()||"";if(!raw)throw new Error("Paste an origin and extended public key for co-signer "+(index+1)+".");
    let parsed=hodlParseMultisigCosigner(raw);if(parsed.isPrivate)throw new Error("Co-signer "+(index+1)+" is an extended private key. Paste only an extended public key.");
    if(parsed.network!==network)throw new Error(`Co-signer ${index+1}'s ${parsed.prefix} is for ${parsed.network}, but this multisig is set to ${network}.`);
    if(!hodlMultisigPrefixCompatible(parsed,kind))throw new Error(parsed.scope==="singlesig"?`Co-signer ${index+1} uses a singlesig ${parsed.prefix}. Use a generic ${cr[network].x.pubName}, or the proper uppercase multisig export for this script type.`:`Co-signer ${index+1}'s ${parsed.prefix} does not match the selected multisig script type.`);
    let accountError=hodlMultisigAccountKeyError(parsed,kind,legacyStandard);if(accountError)throw new Error(`Co-signer ${index+1}: ${accountError}`);
    if(!parsed.origin)throw new Error(`Co-signer ${index+1} needs a key origin so a signer can recognize this key. Paste ${hodlMultisigKeyPlaceholder(kind,network,legacyStandard)} as exported by the device.`);
    let originError=hodlOriginMatchesParsedKey(parsed.origin,parsed);if(originError)throw new Error(`Co-signer ${index+1}: ${originError}`);
    let scriptOriginError=hodlOriginScriptError(parsed.origin,kind,network,legacyStandard);if(scriptOriginError)throw new Error(`Co-signer ${index+1}: ${scriptOriginError}`);
    let accountNumber=hodlMultisigAccountNumber(parsed.origin,kind);if(accountNumber!=null)accountNumbers.push(accountNumber);
    let node=parsed.node,canonical=hodlCanonicalMultisigKey(parsed);if(xpubs.includes(canonical))throw new Error(`Co-signer ${index+1} duplicates an earlier co-signer. Every slot must use a distinct extended public key.`);
    nodes.push(node);xpubs.push(canonical);keyTokens.push(hodlMultisigKeyToken(parsed,network))
  }
  let accountSummary=hodlSummarizeMultisigAccounts(accountNumbers),accountWarning=hodlMultisigAccountWarning(accountSummary);
  return{network,count,n,m,kind,legacyStandard,nodes,xpubs,keyTokens,accountSummary,accountWarning}
}
function hodlBuildMsig(){
  let error=document.getElementById("msig-error");error.textContent="";
  try{
    let{network,count,n,m,kind,legacyStandard,nodes,xpubs,keyTokens,accountSummary,accountWarning}=hodlValidatedMsigInputs(),bip45=kind==="p2sh"&&legacyStandard==="bip45";
    let receiveSuffix=bip45?"/0/0/*":"/0/*",changeSuffix=bip45?"/0/1/*":"/1/*";
    let inner=keyTokens.map(key=>key+receiveSuffix).join(","),innerChange=keyTokens.map(key=>key+changeSuffix).join(",");
    let descriptor=kind==="p2wsh"?`wsh(sortedmulti(${m},${inner}))`:kind==="p2sh-p2wsh"?`sh(wsh(sortedmulti(${m},${inner})))`:`sh(sortedmulti(${m},${inner}))`;
    let changeDescriptor=kind==="p2wsh"?`wsh(sortedmulti(${m},${innerChange}))`:kind==="p2sh-p2wsh"?`sh(wsh(sortedmulti(${m},${innerChange})))`:`sh(sortedmulti(${m},${innerChange}))`;
    let receive=[],change=[],receivePath=bip45?"m/0/0/":"m/0/",changePath=bip45?"m/0/1/":"m/1/";for(let index=0;index<count;index++){
      let receivePublicKeys=nodes.map(node=>{let key=node.derive(receivePath+index).publicKey;if(!key)throw new Error("Could not derive a public key");return key});
      let changePublicKeys=nodes.map(node=>{let key=node.derive(changePath+index).publicKey;if(!key)throw new Error("Could not derive a public key");return key});
      receive.push(Object.assign({index,path:receivePath.slice(1)+index},hodlMsigAddr(receivePublicKeys,m,network,kind)));
      change.push(Object.assign({index,path:changePath.slice(1)+index},hodlMsigAddr(changePublicKeys,m,network,kind)))
    }
    let notes=["This is watch-only. Private keys never entered this calculator.","Each key origin lets a signer match its seed to one co-signer.","A signer is only needed when you spend."];
    if(bip45)notes.push("Legacy BIP45 addresses use co-signer branch 0 for this receive and change set.");
    if(kind==="p2sh"&&legacyStandard==="bip87")notes.push("Legacy P2SH uses the selected BIP87 account paths. Keep the descriptor with every seed backup.");
    re={kind:"msig",network,m,n,script:kind,scriptStandard:kind==="p2sh"?legacyStandard:"bip48",account:accountSummary.account,accountMixed:accountSummary.mixed,xpubs,receiveDescriptor:Le(descriptor),changeDescriptor:Le(changeDescriptor),walletDescriptor:hodlWatchOnlyMultipathDescriptor(Le(descriptor)),receive,change,notes,warnings:accountWarning?[accountWarning]:[]};
    hodlCaptureMsig();hodlShowMsig();hodlFocusWalletResult()
  }catch(exception){re=null;dr.innerHTML="";error.textContent=exception.message||String(exception);hodlCaptureMsig()}
}
function hodlShowMsig(){if(!re||re.kind!=="msig")return;Ge=!1;let accountLabel=re.accountMixed?" · Account Mixed":re.account==null?"":` · Account ${re.account}`,standardLabel=re.scriptStandard?` · ${re.scriptStandard.toUpperCase()}`:"";dr.innerHTML=`
    <section class="card account-result-card">
      <div class="kicker">${re.m}-of-${re.n} multisig${standardLabel} · ${re.network}${accountLabel}</div>
      <h2 tabindex="-1">Your multisig receive wallet</h2>
      <p class="muted">Anyone can pay these addresses. Spending later needs ${re.m} signature${re.m===1?"":"s"} from the configured ${re.n} signing key${re.n===1?"":"s"}. This screen has no private keys.</p>
      ${hodlWalletMessages(re,"multisig")}
      <section class="account-result-section account-watch-section" aria-labelledby="multisig-watch-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-watch-heading">Watch-only wallet data</h3>
          <p class="muted">These descriptors reveal every receive and change address for this multisig, but cannot authorize spending.</p>
        </div>
        ${hodlWatchOnlyDescriptorExport(re.receiveDescriptor,re.changeDescriptor)}
      </section>
      <section class="account-result-section account-address-section" aria-labelledby="multisig-address-heading">
        <div class="wallet-data-section-head">
          <h3 id="multisig-address-heading">Addresses</h3>
          <p class="muted">Verify the first receive address on every signing device before accepting bitcoin.</p>
        </div>
        ${re.receive[0]?`<div class="account-address-lead"><h4 class="wallet-data-subtitle">Receive address #0</h4><div class="qr" aria-label="Multisig receive address 0 QR code">${an(re.receive[0].address)}</div><p class="mono">${$t(re.receive[0].address)}</p><p class="muted mono">${$t(re.receive[0].path)}</p></div>`:""}
        <h4 class="wallet-data-subtitle">Receive</h4>
        ${hodlAddressTable(re.receive,"Multisig receive addresses")}
        <h4 class="wallet-data-subtitle">Change</h4>
        ${hodlAddressTable(re.change,"Multisig change addresses")}
      </section>
      <p class="muted">Import the watch-only wallet descriptor into Sparrow or another wallet.</p>
    </section>`}

function hodlDiceCompare(){}
var hodlPsbtPriv=null,hodlPsbtHd=null,hodlPsbtSource="",hodlPsbtNote="No session key. Inspect-only mode.";
function hodlPsbtNeed(bytes,offset,length,message){if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<0||offset+length>bytes.length)throw new Error(message||"PSBT ended early.")}
function hodlU32(number){let bytes=new Uint8Array(4);new DataView(bytes.buffer).setUint32(0,number>>>0,!0);return bytes}
function hodlU64(number){let bytes=new Uint8Array(8),value=BigInt(number);if(value<0n)throw new Error("Negative transaction amount.");for(let i=0;i<8;i++){bytes[i]=Number(value&255n);value>>=8n}if(value)throw new Error("Transaction amount is too large.");return bytes}
function hodlR32(bytes,offset){hodlPsbtNeed(bytes,offset,4,"PSBT ended inside a 32-bit value.");return new DataView(bytes.buffer,bytes.byteOffset+offset,4).getUint32(0,!0)}
function hodlR64(bytes,offset){hodlPsbtNeed(bytes,offset,8,"PSBT ended inside a 64-bit value.");let value=0n;for(let i=0;i<8;i++)value|=BigInt(bytes[offset+i])<<BigInt(8*i);return value}
function hodlVarInt(bytes,offset){
  hodlPsbtNeed(bytes,offset,1);let marker=bytes[offset];
  if(marker<253)return[marker,offset+1];
  if(marker===253){hodlPsbtNeed(bytes,offset+1,2);let value=bytes[offset+1]|bytes[offset+2]<<8;if(value<253)throw new Error("Non-canonical compact integer.");return[value,offset+3]}
  if(marker===254){let value=hodlR32(bytes,offset+1);if(value<=65535)throw new Error("Non-canonical compact integer.");return[value,offset+5]}
  let value=hodlR64(bytes,offset+1);if(value<=0xffffffffn)throw new Error("Non-canonical compact integer.");if(value>BigInt(Number.MAX_SAFE_INTEGER))throw new Error("PSBT field is too large for EntropyLab.");return[Number(value),offset+9]
}
function hodlVarIntBytes(number){if(!Number.isSafeInteger(number)||number<0)throw new Error("Invalid compact integer.");if(number<253)return Uint8Array.of(number);if(number<=65535)return Uint8Array.of(253,number&255,number>>8&255);if(number<=0xffffffff){let bytes=new Uint8Array(5);bytes[0]=254;bytes.set(hodlU32(number),1);return bytes}throw new Error("Compact integer is too large.")}
function hodlPushScript(script){return Os(hodlVarIntBytes(script.length),script)}
function hodlH256(bytes){return Z(Z(bytes))}
function hodlEq(a,b){if(!a||!b||a.length!==b.length)return!1;let difference=0;for(let i=0;i<a.length;i++)difference|=a[i]^b[i];return difference===0}
function hodlHexRev(bytes){let copy=new Uint8Array(bytes);copy.reverse();return M.encode(copy)}
function hodlB64(value){let binary=atob(value),bytes=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);return bytes}
function hodlPsbtBytes(raw){
  let value=raw.trim(),compact=value.replace(/\s/g,"");if(!value)throw new Error("Paste a PSBT v0.");if(compact.length>7000000)throw new Error("This PSBT is too large to inspect safely.");
  let bytes;if(/^[0-9a-fA-F]+$/.test(compact)&&compact.length%2===0&&compact.length>=10)bytes=M.decode(compact.toLowerCase());else try{bytes=hodlB64(compact)}catch{throw new Error("That does not look like a PSBT in base64 or hex.")}
  if(bytes.length>5000000)throw new Error("This PSBT is too large to inspect safely.");return bytes
}
function hodlReadMap(bytes,offset){
  let entries=[],keys=new Set;
  for(;;){if(entries.length>=10000)throw new Error("PSBT map has too many entries to inspect safely.");let[keyLength,keyStart]=hodlVarInt(bytes,offset);if(keyLength===0)return{entries,next:keyStart};hodlPsbtNeed(bytes,keyStart,keyLength,"PSBT ended inside a key.");let key=bytes.slice(keyStart,keyStart+keyLength),keyHex=M.encode(key);if(keys.has(keyHex))throw new Error("PSBT contains a duplicate key.");keys.add(keyHex);offset=keyStart+keyLength;let[valueLength,valueStart]=hodlVarInt(bytes,offset);hodlPsbtNeed(bytes,valueStart,valueLength,"PSBT ended inside a value.");let value=bytes.slice(valueStart,valueStart+valueLength);offset=valueStart+valueLength;entries.push({type:key[0],keydata:key.slice(1),key,val:value})}
}
function hodlTx(bytes){
  let offset=0,version=hodlR32(bytes,offset);offset+=4;hodlPsbtNeed(bytes,offset,2,"Unsigned transaction ended early.");if(bytes[offset]===0&&bytes[offset+1]===1)throw new Error("The PSBT v0 unsigned transaction must not contain a witness marker.");
  let[inputCount,inputStart]=hodlVarInt(bytes,offset);if(inputCount>100000)throw new Error("Unsigned transaction has too many inputs.");offset=inputStart;let inputs=[];
  for(let i=0;i<inputCount;i++){hodlPsbtNeed(bytes,offset,36,"Unsigned transaction ended inside an input.");let txid=bytes.slice(offset,offset+32);offset+=32;let vout=hodlR32(bytes,offset);offset+=4;let[scriptLength,scriptStart]=hodlVarInt(bytes,offset);hodlPsbtNeed(bytes,scriptStart,scriptLength+4,"Unsigned transaction ended inside an input.");let script=bytes.slice(scriptStart,scriptStart+scriptLength);if(script.length)throw new Error("PSBT v0 unsigned transaction inputs must have empty scriptSigs.");offset=scriptStart+scriptLength;let sequence=hodlR32(bytes,offset);offset+=4;inputs.push({txid,vout,script,sequence})}
  let[outputCount,outputStart]=hodlVarInt(bytes,offset);if(outputCount>100000)throw new Error("Unsigned transaction has too many outputs.");offset=outputStart;let outputs=[];
  for(let i=0;i<outputCount;i++){let amount=hodlR64(bytes,offset);offset+=8;let[scriptLength,scriptStart]=hodlVarInt(bytes,offset);hodlPsbtNeed(bytes,scriptStart,scriptLength,"Unsigned transaction ended inside an output.");let script=bytes.slice(scriptStart,scriptStart+scriptLength);offset=scriptStart+scriptLength;outputs.push({amount,script})}
  let locktime=hodlR32(bytes,offset);offset+=4;if(offset!==bytes.length)throw new Error("Unsigned transaction contains trailing bytes.");return{version,inputs,outputs,locktime,raw:bytes}
}
function hodlParsePsbt(bytes){
  if(bytes.length<5||bytes[0]!==0x70||bytes[1]!==0x73||bytes[2]!==0x62||bytes[3]!==0x74||bytes[4]!==0xff)throw new Error("Not a PSBT. Bitcoin PSBTs start with the bytes psbt followed by ff.");
  let offset=5,globalMap=hodlReadMap(bytes,offset);offset=globalMap.next;let versionEntry=globalMap.entries.find(entry=>entry.type===0xfb&&entry.keydata.length===0);if(versionEntry){if(versionEntry.val.length!==4||hodlR32(versionEntry.val,0)!==0)throw new Error("EntropyLab currently supports PSBT v0 only.")}
  let unsignedEntries=globalMap.entries.filter(entry=>entry.type===0&&entry.keydata.length===0);if(unsignedEntries.length!==1)throw new Error("This PSBT must contain exactly one unsigned transaction.");let tx=hodlTx(unsignedEntries[0].val),inputs=[],outputs=[];
  for(let i=0;i<tx.inputs.length;i++){if(offset>=bytes.length)throw new Error("PSBT is missing an input map.");let map=hodlReadMap(bytes,offset);offset=map.next;inputs.push(map.entries)}
  for(let i=0;i<tx.outputs.length;i++){if(offset>=bytes.length)throw new Error("PSBT is missing an output map.");let map=hodlReadMap(bytes,offset);offset=map.next;outputs.push(map.entries)}
  if(offset!==bytes.length)throw new Error("PSBT contains trailing data or extra maps.");return{tx,global:globalMap.entries,inputs,outputs}
}
function hodlSats(number){let value=typeof number==="bigint"?number:BigInt(number),negative=value<0n;if(negative)value=-value;let whole=value/100000000n,fraction=value%100000000n;return(negative?"-":"")+whole.toString()+"."+fraction.toString().padStart(8,"0")}
function hodlAddr(script,network){try{return or(_s(network)).encode(Oe.decode(script))}catch{return"script "+M.encode(script)}}
function hodlFind(entries,type){return entries.filter(entry=>entry.type===type)}
function hodlWitUtxo(entries){let entry=hodlFind(entries,1).find(item=>item.keydata.length===0);if(!entry)return null;if(entry.val.length<9)throw new Error("A witness UTXO field is truncated.");let amount=hodlR64(entry.val,0),parsed=hodlVarInt(entry.val,8),scriptLength=parsed[0],scriptStart=parsed[1];hodlPsbtNeed(entry.val,scriptStart,scriptLength,"A witness UTXO script is truncated.");if(scriptStart+scriptLength!==entry.val.length)throw new Error("A witness UTXO contains trailing bytes.");return{amount,script:entry.val.slice(scriptStart)}}
function hodlPartialSigs(entries){return hodlFind(entries,2).map(entry=>{let signature=entry.val;if(signature.length<2)return{pubkey:entry.keydata,der:new Uint8Array,sighash:0,raw:signature};return{pubkey:entry.keydata,der:signature.slice(0,-1),sighash:signature[signature.length-1],raw:signature}})}
function hodlTapSigs(entries){return hodlFind(entries,0x13).concat(hodlFind(entries,0x14))}
function hodlFinalized(entries){return entries.some(entry=>entry.type===7||entry.type===8)}
function hodlBip32(entries,pubkey){return hodlFind(entries,6).filter(entry=>!pubkey||hodlEq(entry.keydata,pubkey)).map(entry=>{if(entry.val.length<4||(entry.val.length-4)%4)throw new Error("A BIP32 derivation path is malformed.");let path=[];for(let i=4;i<entry.val.length;i+=4)path.push(new DataView(entry.val.buffer,entry.val.byteOffset+i,4).getUint32(0,!0));return{pubkey:entry.keydata,fingerprint:entry.val.slice(0,4),path}})}
function hodlInputScriptCode(entries,witnessUtxo){
  if(!witnessUtxo)return null;let outputScript=witnessUtxo.script,redeem=(hodlFind(entries,4).find(entry=>entry.keydata.length===0)||{}).val,witnessScript=(hodlFind(entries,5).find(entry=>entry.keydata.length===0)||{}).val,program=null;
  if(outputScript.length===22&&outputScript[0]===0&&outputScript[1]===20)program=outputScript;
  else if(redeem&&redeem.length===22&&redeem[0]===0&&redeem[1]===20)program=redeem;
  if(program)return Os(Uint8Array.of(0x76,0xa9,0x14),program.slice(2),Uint8Array.of(0x88,0xac));
  let isWitnessScript=outputScript.length===34&&outputScript[0]===0&&outputScript[1]===32||redeem&&redeem.length===34&&redeem[0]===0&&redeem[1]===32;return isWitnessScript&&witnessScript?witnessScript:null
}
function hodlBip143(tx,index,scriptCode,amount,sighashType){
  if(sighashType!==1)return null;let prevouts=[],sequences=[],outputs=[];for(let input of tx.inputs){prevouts.push(input.txid,hodlU32(input.vout));sequences.push(hodlU32(input.sequence))}for(let output of tx.outputs)outputs.push(hodlU64(output.amount),hodlPushScript(output.script));let input=tx.inputs[index];
  return hodlH256(Os(hodlU32(tx.version),hodlH256(Os(...prevouts)),hodlH256(Os(...sequences)),input.txid,hodlU32(input.vout),hodlPushScript(scriptCode),hodlU64(amount),hodlU32(input.sequence),hodlH256(Os(...outputs)),hodlU32(tx.locktime),hodlU32(sighashType)))
}
function hodlSigParts(der){try{let compact=xe.Signature.fromBytes(der,"der").toBytes("compact");return{r:compact.slice(0,32),s:compact.slice(32)}}catch{return null}}
function hodlPrivForPub(pubkey){if(hodlPsbtPriv){let compressed=xe.getPublicKey(hodlPsbtPriv,!0),uncompressed=xe.getPublicKey(hodlPsbtPriv,!1);if(hodlEq(compressed,pubkey)||hodlEq(uncompressed,pubkey))return hodlPsbtPriv}if(hodlPsbtHd){try{let rootPubkey=hodlPsbtHd.publicKey;if(rootPubkey&&hodlEq(rootPubkey,pubkey))return hodlPsbtHd.privateKey}catch{}}return null}
function hodlPrivFromPath(entries,pubkey){if(!hodlPsbtHd)return null;let rootFingerprint=Us(hodlPsbtHd.fingerprint);for(let derivation of hodlBip32(entries,pubkey)){if(M.encode(derivation.fingerprint)!==rootFingerprint)continue;try{let node=hodlPsbtHd;for(let index of derivation.path)node=node.deriveChild(index);if(node.publicKey&&hodlEq(node.publicKey,pubkey))return node.privateKey}catch{}}return null}
function hodlPsbtWipeMem(){if(hodlPsbtPriv)try{hodlPsbtPriv.fill(0)}catch{}hodlPsbtPriv=null;if(hodlPsbtHd)try{let privateKey=hodlPsbtHd.privateKey;if(privateKey)privateKey.fill(0)}catch{}hodlPsbtHd=null;hodlPsbtSource="";hodlPsbtNote="No session key. Inspect-only mode."}
function hodlLoadPsbtKey(text,passphrase){
  hodlPsbtWipeMem();let value=text.trim(),hex=value.replace(/\s/g,"").replace(/^0x/i,"");if(!value)return;
  if(/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(value)){let decoded=Ls(value);hodlPsbtPriv=decoded.priv;hf(hodlPsbtPriv);hodlPsbtNote=`Session key: ${decoded.network} WIF. Kept in page memory only.`}
  else if(/^[0-9a-fA-F]{64}$/.test(hex)){hodlPsbtPriv=M.decode(hex.toLowerCase());hf(hodlPsbtPriv);hodlPsbtNote="Session key: 32-byte private key. Kept in page memory only."}
  else{let mnemonic=Mt(value);if(!mnemonic.ok)throw new Error(mnemonic.error||"Enter a BIP39 seed phrase, WIF, or 64-character hex key.");let seed=wi(mnemonic.words.join(" "),passphrase||"");try{hodlPsbtHd=Gt.fromMasterSeed(seed)}finally{seed.fill(0)}hodlPsbtNote="Session key: BIP39 seed"+(passphrase?" + passphrase":"")+". Kept in page memory only."}
  hodlPsbtSource="manual"
}
function hodlUseActiveKeyForPsbt(){
  let state=hodlKeys[hodlActiveKey];if(!state||!state.result)throw new Error("Generate an active key first, then return to PSBT / Nonce.");let result=state.result;hodlPsbtWipeMem();
  if(result.kind==="hd"&&result.mnemonic){let seed=wi(result.mnemonic,state.fields.pass||"");try{hodlPsbtHd=Gt.fromMasterSeed(seed)}finally{seed.fill(0)}}
  else if(result.kind==="hd"&&result.rootXprv)hodlPsbtHd=Gt.fromExtendedKey(uf(result.rootXprv).xkey);
  else if(result.kind==="hd"&&result.importedPrivateKey)throw new Error("The active key is an account-level extended private key. PSBT session signing needs origin-aware relative paths, which this version does not infer. Use the original seed or root xprv/tprv instead.");
  else if(result.kind==="single"&&result.privHex){hodlPsbtPriv=M.decode(result.privHex);hf(hodlPsbtPriv)}
  else throw new Error("The active key has no private material available for a session check.");
  hodlPsbtSource="active";hodlPsbtNote="Session key from "+(state.name||"the active key")+". Kept in page memory only."
}
function hodlInitPsbt(){
  let go=document.getElementById("psbt-go");if(!go)return;go.onclick=hodlRunPsbt;
  document.getElementById("psbt-use-calc").onclick=()=>{let error=document.getElementById("psbt-error");error.textContent="";try{hodlUseActiveKeyForPsbt();document.getElementById("psbt-key").value="";document.getElementById("psbt-pass").value="";document.getElementById("psbt-session").textContent=hodlPsbtNote}catch(exception){error.textContent=exception.message||String(exception)}};
  document.getElementById("psbt-wipe").onclick=()=>{hodlPsbtWipeMem();document.getElementById("psbt-key").value="";document.getElementById("psbt-pass").value="";document.getElementById("psbt-text").value="";document.getElementById("psbt-out").innerHTML="";document.getElementById("psbt-error").textContent="";document.getElementById("psbt-session").textContent="Session ended and accessible fields were cleared (best effort)."};
  let clearSecretFields=()=>{hodlPsbtWipeMem();let key=document.getElementById("psbt-key"),pass=document.getElementById("psbt-pass");if(key)key.value="";if(pass)pass.value=""};addEventListener("pagehide",clearSecretFields);addEventListener("pageshow",event=>{if(event.persisted)clearSecretFields()})
}
function hodlRunPsbt(){
  let error=document.getElementById("psbt-error"),output=document.getElementById("psbt-out"),manual=document.getElementById("psbt-key").value;error.textContent="";output.innerHTML="";
  try{if(manual.trim()){hodlLoadPsbtKey(manual,document.getElementById("psbt-pass").value);document.getElementById("psbt-key").value="";document.getElementById("psbt-pass").value=""}document.getElementById("psbt-session").textContent=hodlPsbtNote;let psbt=hodlParsePsbt(hodlPsbtBytes(document.getElementById("psbt-text").value));output.innerHTML=hodlRenderPsbt(psbt)}catch(exception){error.textContent=exception instanceof Error?exception.message:String(exception)}
}
function hodlRenderPsbt(psbt){
  let network=hodlSelectedNetwork(document.getElementById("psbt-network")),tx=psbt.tx,inputSum=0n,knownInputs=0,html=[],rValues=[],rows=[],tapSignatureCount=0;
  html.push("<p class='label'>Where this transaction sends bitcoin</p>");tx.outputs.forEach((output,index)=>{html.push("<p class='psbt-kv'><strong>Output "+index+"</strong> · "+hodlSats(output.amount)+" BTC<br>"+$t(hodlAddr(output.script,network))+"</p>")});
  psbt.inputs.forEach((entries,index)=>{
    let witnessUtxo=hodlWitUtxo(entries);if(witnessUtxo){inputSum+=witnessUtxo.amount;knownInputs++}let previous=tx.inputs[index],destination=witnessUtxo?hodlAddr(witnessUtxo.script,network):"(previous output details unavailable)",signatures=hodlPartialSigs(entries),tapSignatures=hodlTapSigs(entries),finalized=hodlFinalized(entries);tapSignatureCount+=tapSignatures.length;
    html.push("<p class='psbt-kv'><strong>Input "+index+"</strong> · "+hodlHexRev(previous.txid)+" : "+previous.vout+(witnessUtxo?" · "+hodlSats(witnessUtxo.amount)+" BTC":"")+"<br>"+$t(destination)+"<br>"+(signatures.length+tapSignatures.length?signatures.length+tapSignatures.length+" signature(s) present":finalized?"Finalized input data present":"Not signed yet")+"</p>");
    signatures.forEach(signature=>{
      let parts=hodlSigParts(signature.der),scriptCode=hodlInputScriptCode(entries,witnessUtxo),sighash=witnessUtxo&&scriptCode?hodlBip143(tx,index,scriptCode,witnessUtxo.amount,signature.sighash):null,signatureValid=parts&&sighash?xe.verify(signature.der,sighash,signature.pubkey,{prehash:!1,format:"der",lowS:!1}):null,privateKey=hodlPrivForPub(signature.pubkey)||hodlPrivFromPath(entries,signature.pubkey),message="Need the matching key in this session to check plain RFC 6979.",className="muted";
      if(!parts){message="Signature is not strict DER and its nonce cannot be inspected.";className="psbt-warn"}
      else{rValues.push({input:index,r:parts.r,s:parts.s,hex:M.encode(parts.r),pubkey:signature.pubkey,sighash,valid:signatureValid});if(signatureValid===!1){message="This signature does not verify against the reconstructed input digest.";className="psbt-warn"}else if(privateKey&&sighash)try{let expected=xe.sign(sighash,privateKey,{prehash:!1,extraEntropy:!1}),matches=hodlEq(expected.slice(0,32),parts.r);message=matches?"Matches plain RFC 6979 deterministic signing.":"Does not match plain RFC 6979. Honest signers may add auxiliary randomness; a mismatch alone is not evidence of compromise.";className=matches?"psbt-ok":"psbt-warn"}catch(exception){message="Could not recompute this signature: "+(exception.message||String(exception));className="psbt-warn"}else if(privateKey&&signature.sighash!==1){message="Matching key found, but this check currently supports SIGHASH_ALL without ANYONECANPAY only.";className="psbt-warn"}else if(privateKey&&!scriptCode){message="Matching key found, but this input script is not yet supported for RFC 6979 comparison.";className="psbt-warn"}}
      rows.push({input:index,message,className,pubkey:M.encode(signature.pubkey)})
    })
  });
  if(knownInputs===tx.inputs.length){let outputSum=tx.outputs.reduce((sum,output)=>sum+output.amount,0n),fee=inputSum-outputSum;if(fee>=0n)html.push("<p class='psbt-kv'><strong>Fee (from PSBT fields)</strong> · "+hodlSats(fee)+" BTC</p>");else html.push("<p class='psbt-bad'><strong>Invalid known amounts:</strong> outputs exceed inputs by "+hodlSats(-fee)+" BTC.</p>")}else html.push("<p class='muted'>Fee unknown — some inputs do not include a witness UTXO amount.</p>");
  html.push("<p class='label'>ECDSA nonce check</p>");let reused=[],possible=[];
  for(let first=0;first<rValues.length;first++)for(let second=first+1;second<rValues.length;second++){let a=rValues[first],b=rValues[second];if(!hodlEq(a.pubkey,b.pubkey)||!hodlEq(a.r,b.r))continue;if(a.valid&&b.valid&&a.sighash&&b.sighash&&!hodlEq(a.sighash,b.sighash))reused.push([a,b]);else if(a.input!==b.input)possible.push([a,b])}
  if(reused.length)html.push("<p class='psbt-bad'><strong>Reused nonce detected for the same public key.</strong> The same r value appears on different message digests. If both signatures are valid, the private key can be recovered. Do not broadcast this transaction.</p>");
  else if(possible.length)html.push("<p class='psbt-warn'><strong>Possible repeated nonce for the same public key.</strong> The message digests could not both be reconstructed, so verify these signatures independently before treating this as a key leak.</p>");
  else if(rValues.length>=2)html.push("<p class='psbt-ok'>No repeated ECDSA nonce r values were found for the same public key in this PSBT.</p>");
  else if(rValues.length===1)html.push("<p class='muted'>Only one strict ECDSA signature is present. Nonce reuse cannot be judged from this file alone.</p>");
  else html.push("<p class='muted'>No strict ECDSA signatures are present, so there is no nonce to compare yet.</p>");
  if(rValues.length)html.push("<p class='psbt-kv'>r values:<br>"+rValues.map(value=>$t(value.hex)+" (input "+value.input+")").join("<br>")+"</p>");
  rows.forEach(row=>html.push("<p class='"+row.className+"'><strong>Input "+row.input+"</strong> pubkey "+$t(row.pubkey.slice(0,18))+"… — "+$t(row.message)+"</p>"));
  if(tapSignatureCount)html.push("<p class='muted'>This PSBT also contains "+tapSignatureCount+" Taproot / Schnorr signature(s). They are counted but their BIP340 nonces are not analyzed in this version.</p>");
  html.push("<p class='muted'>Plain RFC 6979 comparison currently covers SegWit v0 P2WPKH and P2WSH signatures using SIGHASH_ALL. Nonce reuse detection compares strict DER ECDSA signatures from the same public key.</p>");return html.join("")
}
var hodlAccountId="bip84",hodlNextKeyId=1,hodlNextKeyNumber=1,hodlKeys=[],hodlActiveKey=-1;
function hodlKeyColor(id){let hue=Math.round((Number(id)*137.508+19)%360);return`oklch(61% 0.08 ${hue})`}
function hodlNewKeyState(name,keyId,keyNumber){let id=keyId??hodlNextKeyId++,number=keyNumber??hodlNextKeyNumber++;return{id,number,color:hodlKeyColor(id),name:name||hodlDefaultKeyName(number),mode:"dice",diceMethod:"coldcard",entropyFormat:"hex",seedAutocomplete:!1,dplusNumberedD16:!1,padShuffle:!1,targetWords:24,diceCoinPositions:[],lastWord:"",dplusLastWord:"",result:null,reveal:!1,accountId:"bip84",error:"",fields:{pass:"",script:"bip84",network:"mainnet",account:"0",count:"5",dice:"",dplusDice:"",hex:"",bin:"",seed:"",key:"",keyKind:"wif-or-hex"}}}
function hodlRestoreFormFields(state){
  if(!state)return;
  document.querySelectorAll("input[name=kk]").forEach(input=>{input.checked=input.value===(state.fields.keyKind||"wif-or-hex")});
  let seedAutocomplete=document.getElementById("seed-autocomplete");if(seedAutocomplete)seedAutocomplete.checked=Boolean(state.seedAutocomplete);
  let dplusToggle=document.getElementById("dplus-numbered-d16");if(dplusToggle)dplusToggle.checked=Boolean(state.dplusNumberedD16);
  let padToggle=document.getElementById("pad-shuffle-toggle");if(padToggle)padToggle.checked=Boolean(state.padShuffle);
  ["dice","hex","bin","seed","key"].forEach(id=>{let el=document.getElementById(id);if(el){el.value=id==="dice"&&ge==="dplus"?state.fields.dplusDice||"":state.fields[id]||"";if(id==="dice"){el.dataset.previousValue=el.value;el.setSelectionRange(el.value.length,el.value.length)}el.dispatchEvent(new Event("input"))}});
}
function hodlSetMode(mode){
  hodlCaptureKey();
  let state=hodlKeys[hodlActiveKey];if(state)state.mode=mode;
  Ne=mode;hodlEntropyFormat=state?.entropyFormat==="bin"?"bin":"hex";[...Zs.children].forEach((button,index)=>{let active=["dice","hex","seed","key"][index]===Ne;button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active))});
  hodlRenderKeyForm();hodlRestoreFormFields(state);hodlUpdateSeedLengthControl();hodlUpdateDerivationPathPreview();hodlQueueSegmentedControlSync();
}
function hodlKeyStateNeedsClear(state){
  if(!state)return!1;let fields=state.fields||{},hasText=id=>String(fields[id]??"").length>0;
  return String(state.mode??"dice")!=="dice"||String(state.diceMethod??"coldcard")!=="coldcard"||String(state.entropyFormat??"hex")!=="hex"||Boolean(state.seedAutocomplete)||Boolean(state.dplusNumberedD16)||Number(state.targetWords??24)!==24||
    (Array.isArray(state.diceCoinPositions)&&state.diceCoinPositions.length>0)||String(state.lastWord??"").length>0||String(state.dplusLastWord??"").length>0||Boolean(state.result)||Boolean(state.reveal)||String(state.error??"").length>0||
    String(state.accountId??"bip84")!=="bip84"||String(fields.script??"bip84")!=="bip84"||String(fields.network??"mainnet")!=="mainnet"||String(fields.account??"0")!=="0"||String(fields.count??"5")!=="5"||
    String(fields.keyKind??"wif-or-hex")!=="wif-or-hex"||["pass","dice","dplusDice","hex","bin","seed","key"].some(hasText)
}
function hodlSyncKeyClearButton(capture=!1){
  if(capture)hodlCaptureKey();let button=document.getElementById("wipe");if(!button)return;
  button.disabled=!hodlKeyStateNeedsClear(hodlKeys[hodlActiveKey]);button.setAttribute("aria-disabled",String(button.disabled))
}
function hodlWipeActiveKey(){
  if(hodlActiveKey<0||!hodlKeys[hodlActiveKey])return;
  let state=hodlKeys[hodlActiveKey];hodlKeys[hodlActiveKey]=hodlNewKeyState(state.name,state.id,state.number);hodlRestoreKey();
}
function hodlCaptureKey(){
  if(hodlActiveKey<0||!hodlKeys[hodlActiveKey])return;
  let state=hodlKeys[hodlActiveKey];
  state.mode=Ne;state.diceMethod=ge;state.entropyFormat=hodlEntropyFormat;let seedAutocomplete=document.getElementById("seed-autocomplete");if(seedAutocomplete)state.seedAutocomplete=seedAutocomplete.checked;  let dplusToggle=document.getElementById("dplus-numbered-d16");if(dplusToggle)hodlDPlusNumberedD16=dplusToggle.checked;state.dplusNumberedD16=Boolean(hodlDPlusNumberedD16);state.padShuffle=hodlPadShuffle;state.targetWords=Pt;state.diceCoinPositions=hodlDiceCoinPositions.slice();if(ge==="dplus")state.dplusLastWord=ft;else if(ge==="bitbox")state.lastWord=ft;state.result=re;state.reveal=Ge;state.accountId=hodlSelectedScriptType();state.fields.script=state.accountId;
  state.error=document.getElementById("error")?.textContent||"";
  ["pass","account","count","hex","bin","seed","key"].forEach(id=>{let el=document.getElementById(id);if(el)state.fields[id]=el.value});state.fields.network=hodlSelectedNetwork(document.getElementById("network"));
  let dice=document.getElementById("dice");if(dice)state.fields[ge==="dplus"?"dplusDice":"dice"]=dice.value;
  state.fields.keyKind=document.querySelector("input[name=kk]:checked")?.value||state.fields.keyKind||"wif-or-hex";
}
function hodlSyncSelect(select,value){
  if(!select)return;
  select.value=value;
  select.dispatchEvent(new Event("entropylab:sync-select"));
}
function hodlSelectedNetwork(select){
  return select?.value==="testnet"?"testnet":"mainnet"
}
function hodlRestoreKey(){
  let state=hodlKeys[hodlActiveKey];
  if(!state){
    Ne="dice";ge="coldcard";hodlEntropyFormat="hex";hodlDPlusNumberedD16=!1;hodlPadShuffle=!1;Pt=24;hodlDiceCoinPositions=[];ft="";re=null;Ge=!1;hodlAccountId="bip84";
    [...Zs.children].forEach((button,index)=>{let active=index===0;button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active))});hodlRenderKeyForm();
    let pass=document.getElementById("pass");if(pass)pass.value="";
    hodlSyncSelect(document.getElementById("script-type"),"bip84");hodlSyncSelect(document.getElementById("network"),"mainnet");let account=document.getElementById("account");if(account)account.value="0";hodlSyncSelect(document.getElementById("count"),"5");
    W("#error").textContent="";dr.innerHTML="";document.getElementById("calc-card").hidden=!0;hodlQueueMasterFingerprintPreview(0);hodlUpdateDerivationPathPreview();hodlSyncKeyClearButton();hodlSyncDeriveButton();return
  }
  Ne=state.mode;ge=state.diceMethod;hodlEntropyFormat=state.entropyFormat==="bin"?"bin":"hex";hodlDPlusNumberedD16=Boolean(state.dplusNumberedD16);hodlPadShuffle=Boolean(state.padShuffle);Pt=hodlSeedLengths[Number(state.targetWords)]?Number(state.targetWords):24;hodlDiceCoinPositions=hodlNormalizeDiceCoinPositions(state.diceCoinPositions);ft=ge==="dplus"?state.dplusLastWord||"":ge==="bitbox"?state.lastWord||"":"";
  [...Zs.children].forEach((button,index)=>{let active=["dice","hex","seed","key"][index]===Ne;button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active))});
  hodlRenderKeyForm();
  let pass=document.getElementById("pass");if(pass)pass.value=state.fields.pass||"";
  hodlAccountId=state.accountId||state.fields.script||"bip84";
  hodlSyncSelect(document.getElementById("script-type"),hodlAccountId);
  state.fields.network=state.fields.network==="testnet"?"testnet":"mainnet";hodlSyncSelect(document.getElementById("network"),state.fields.network);
  let account=document.getElementById("account");if(account)account.value=state.fields.account??"0";
  hodlSyncSelect(document.getElementById("count"),state.fields.count||"5");
  hodlRestoreFormFields(state);
  re=state.result;Ge=state.reveal;
  document.getElementById("calc-card").hidden=!1;
  W("#error").textContent=state.error||"";
  tc();
  hodlQueueMasterFingerprintPreview(0);hodlUpdateDerivationPathPreview();hodlSyncKeyClearButton();hodlSyncDeriveButton();
}
function hodlKeyTabKeydown(event,index){
  if(event.key==="F2"){event.preventDefault();if(index===hodlActiveKey)hodlBeginKeyRename(index);return}
  let next=null,length=hodlKeys.length;
  if(event.key==="ArrowRight")next=(index+1)%length;
  else if(event.key==="ArrowLeft")next=(index-1+length)%length;
  else if(event.key==="Home")next=0;
  else if(event.key==="End")next=length-1;
  if(next===null)return;
  event.preventDefault();hodlSelectKey(next);W("#key-tabs").children[next]?.focus();
}
var hodlKeySilhouette="M512 176c0 97.2-78.8 176-176 176-11.2 0-22.2-1.1-32.8-3.1l-24 27c-4.4 4.9-10.8 8.1-17.9 8.1H224v40c0 13.3-10.7 24-24 24h-40v40c0 13.3-10.7 24-24 24H24c-13.3 0-24-10.7-24-24v-78.1c0-6.4 2.5-12.5 7-17l161.8-161.8c-5.7-17.4-8.8-35.9-8.8-55.2C160 78.8 238.8 0 336 0s176 78.8 176 176zM374 112a54 54 0 1 0 0 108 54 54 0 1 0 0-108z";
function hodlCreateKeyIcon(color){
  let ns="http://www.w3.org/2000/svg",span=document.createElement("span"),svg=document.createElementNS(ns,"svg"),path=document.createElementNS(ns,"path");
  span.className="key-tab-icon";span.style.color=color;span.setAttribute("aria-hidden","true");
  svg.setAttribute("viewBox","0 0 512 512");svg.setAttribute("fill","currentColor");svg.setAttribute("focusable","false");svg.setAttribute("aria-hidden","true");
  path.setAttribute("data-part","key-silhouette");path.setAttribute("fill-rule","evenodd");path.setAttribute("clip-rule","evenodd");path.setAttribute("d",hodlKeySilhouette);
  svg.appendChild(path);span.appendChild(svg);return span;
}
function hodlCreateMsigIcon(){
  let ns="http://www.w3.org/2000/svg",darkest="#4b4f55",middle="#888d94",span=document.createElement("span"),svg=document.createElementNS(ns,"svg");
  span.className="multisig-tab-icon";span.setAttribute("aria-hidden","true");svg.setAttribute("viewBox","0 -4 49 40");svg.setAttribute("focusable","false");svg.setAttribute("aria-hidden","true");svg.setAttribute("data-keyhole-cx","34");svg.setAttribute("data-keyhole-cy","10.5");svg.setAttribute("data-keyhole-r","2.808");
  let ring=document.createElementNS(ns,"path");ring.setAttribute("data-part","keychain-ring");ring.setAttribute("d","M32.14 7.53 A7.78 7.78 0 1 1 36.97 12.36");ring.setAttribute("fill","none");ring.setAttribute("stroke",middle);ring.setAttribute("stroke-width","1.7");ring.setAttribute("stroke-linecap","round");ring.setAttribute("stroke-linejoin","round");svg.appendChild(ring);
  [["key-back",darkest,-28],["key-middle",middle,0],["key-front","#d1d4d8",28]].forEach(([part,fill,angle])=>{let path=document.createElementNS(ns,"path");path.setAttribute("data-part",part);path.setAttribute("d",hodlKeySilhouette);path.setAttribute("fill",fill);path.setAttribute("fill-rule","evenodd");path.setAttribute("clip-rule","evenodd");path.setAttribute("transform","translate(34 10.5) rotate("+angle+") scale(.052) translate(-374 -166)");svg.appendChild(path)});
  let thread=document.createElementNS(ns,"path");thread.setAttribute("data-part","keychain-thread");thread.setAttribute("d","M36.97 12.36 A7.78 7.78 0 0 0 45 10.5");thread.setAttribute("fill","none");thread.setAttribute("stroke",middle);thread.setAttribute("stroke-width","1.7");thread.setAttribute("stroke-linecap","round");thread.setAttribute("stroke-linejoin","round");svg.appendChild(thread);span.appendChild(svg);return span;
}
function hodlCreateKeyTab(index){
  let state=hodlKeys[index],active=index===hodlActiveKey,button=document.createElement("button"),name=state.name||"Key "+state.number,label=document.createElement("span");
  button.type="button";button.id="key-tab-"+(index+1);button.className="tab key-tab"+(active?" active":"");button.style.setProperty("--key-color",state.color);label.className="key-tab-label";label.textContent=name;button.append(hodlCreateKeyIcon(state.color),label);
  button.dataset.keyNumber=String(state.number);
  button.setAttribute("role","tab");button.setAttribute("aria-controls","calc-card");button.setAttribute("aria-selected",String(active));
  button.setAttribute("aria-label",name+(active?", selected. Activate or press F2 to rename.":". Activate to select."));
  button.title=active?"Click again or press F2 to rename":"Click to select";button.tabIndex=active?0:-1;
  button.onclick=()=>index===hodlActiveKey?hodlBeginKeyRename(index):hodlSelectKey(index);
  button.onkeydown=event=>hodlKeyTabKeydown(event,index);
  return button;
}
function hodlSizeKeyTabEditor(input){
  input.style.width="1px";input.style.width=Math.max(72,input.scrollWidth+2)+"px";
}
function hodlNormalizeKeyName(name){return String(name||"").trim().replace(/\s+/g," ").toLowerCase()}
function hodlKeyNameTaken(name,index){let normalized=hodlNormalizeKeyName(name);return!!normalized&&hodlKeys.some((state,stateIndex)=>stateIndex!==index&&hodlNormalizeKeyName(state.name)===normalized)}
function hodlDefaultKeyName(number){let base="Key "+number,name=base,suffix=2;while(hodlKeyNameTaken(name,-1)){name=base+" ("+suffix+")";suffix++}return name}
function hodlBeginKeyRename(index){
  if(index!==hodlActiveKey||!hodlKeys[index])return;
  let box=W("#key-tabs"),tab=box.children[index];if(!tab||tab.classList.contains("key-tab-editing"))return;
  let state=hodlKeys[index],editor=document.createElement("div"),input=document.createElement("input"),previous=state.name||"Key "+state.number;
  editor.id="key-tab-"+(index+1);editor.className="key-tab key-tab-editing active";editor.style.setProperty("--key-color",state.color);editor.dataset.keyNumber=String(state.number);editor.setAttribute("role","tab");editor.setAttribute("aria-selected","true");editor.setAttribute("aria-controls","calc-card");
  input.type="text";input.className="key-tab-name-input";input.value=previous;input.maxLength=120;
  input.setAttribute("aria-label","Rename "+previous);input.setAttribute("aria-controls","calc-card");
  let finish=(commit,focus)=>{if(!editor.isConnected)return;let name=input.value.trim().replace(/\s+/g," ");if(commit&&name&&!hodlKeyNameTaken(name,index))state.name=name;let button=hodlCreateKeyTab(index);editor.replaceWith(button);if(focus)button.focus()};
  input.oninput=()=>hodlSizeKeyTabEditor(input);
  input.onkeydown=event=>{if(event.key==="Enter"){event.preventDefault();finish(!0,!0)}else if(event.key==="Escape"){event.preventDefault();finish(!1,!0)}};
  input.onblur=()=>finish(!0,!1);editor.append(hodlCreateKeyIcon(state.color),input);tab.replaceWith(editor);hodlSizeKeyTabEditor(input);input.focus();input.select();
}
function hodlRevealTab(box,index){let tab=box.children[index];if(!tab)return;let start=tab.offsetLeft,end=start+tab.offsetWidth,left=box.scrollLeft,right=left+box.clientWidth,target=left;if(start<left)target=start;else if(end>right)target=end-box.clientWidth;if(target!==left)box.scrollTo({left:target,behavior:"smooth"})}
function hodlSyncKeyDeleteButton(){let button=W("#delete-key");if(!button)return;button.disabled=hodlKeys.length<=1;button.setAttribute("aria-disabled",String(button.disabled))}
function hodlRenderKeyTabs(){
  let box=W("#key-tabs"),panel=W("#calc-card");box.innerHTML="";panel.removeAttribute("aria-labelledby");
  box.setAttribute("role","tablist");hodlKeys.forEach((state,index)=>{let button=hodlCreateKeyTab(index);box.appendChild(button);if(index===hodlActiveKey)panel.setAttribute("aria-labelledby",button.id)});
  hodlRevealTab(box,hodlActiveKey);hodlSyncKeyDeleteButton();
}
function hodlSelectKey(index){
  if(index===hodlActiveKey||!hodlKeys[index])return;
  hodlCaptureKey();hodlActiveKey=index;hodlRenderKeyTabs();hodlRestoreKey();
}
function hodlAddKey(){
  hodlCaptureKey();hodlKeys.push(hodlNewKeyState());hodlActiveKey=hodlKeys.length-1;hodlRenderKeyTabs();hodlRestoreKey();
}
function hodlDeleteActiveKey(){
  if(hodlKeys.length<=1||hodlActiveKey<0||!hodlKeys[hodlActiveKey]){hodlSyncKeyDeleteButton();return}
  let deletedIndex=hodlActiveKey,deletedState=hodlKeys[deletedIndex];
  hodlKeys.splice(deletedIndex,1);
  hodlNextKeyNumber=hodlKeys.length?hodlKeys.reduce((latest,state)=>Math.max(latest,state.number),0)+1:deletedState.number;
  hodlActiveKey=hodlKeys.length?Math.min(deletedIndex,hodlKeys.length-1):-1;
  hodlRenderKeyTabs();hodlRestoreKey();
  (hodlActiveKey>=0?W("#key-tabs").children[hodlActiveKey]:W("#add-key"))?.focus();
}
var hodlNextMsigId=1,hodlNextMsigNumber=1,hodlMsigs=[],hodlActiveMsig=-1;
function hodlNewMsigState(name,msigId,msigNumber){let id=msigId??hodlNextMsigId++,number=msigNumber??hodlNextMsigNumber++;return{id,number,name:name||hodlDefaultMsigName(number),result:null,error:"",fields:{m:"2",n:"3",script:"p2wsh",legacyBip87:!1,xpubs:["","",""],network:"mainnet",count:"5"}}}
function hodlMsigStateNeedsClear(state){
  if(!state)return!1;let fields=state.fields||{},xpubs=Array.isArray(fields.xpubs)?fields.xpubs:[];
  return Boolean(state.result)||String(state.error??"").length>0||xpubs.some(value=>String(value??"").length>0)||
    String(fields.m??"2")!=="2"||String(fields.n??"3")!=="3"||String(fields.script??"p2wsh")!=="p2wsh"||Boolean(fields.legacyBip87)||String(fields.network??"mainnet")!=="mainnet"||String(fields.count??"5")!=="5"
}
function hodlSyncMsigClearButton(capture=!1){
  if(capture)hodlCaptureMsig();let button=document.getElementById("msig-wipe");if(!button)return;
  button.disabled=!hodlMsigStateNeedsClear(hodlMsigs[hodlActiveMsig]);button.setAttribute("aria-disabled",String(button.disabled))
}
function hodlCaptureMsig(){
  if(hodlActiveMsig<0||!hodlMsigs[hodlActiveMsig])return;
  let state=hodlMsigs[hodlActiveMsig];
  state.fields.n=document.getElementById("msig-n").value||"3";state.fields.m=document.getElementById("msig-m").value||"2";state.fields.script=hodlScriptKind();state.fields.legacyBip87=hodlSelectedLegacyMultisigStandard()==="bip87";hodlMergeMsigXpubs(state);state.fields.network=hodlSelectedNetwork(document.getElementById("msig-network"));state.fields.count=document.getElementById("msig-count").value||"5";
  state.result=re&&re.kind==="msig"?re:null;state.error=document.getElementById("msig-error").textContent||"";
}
function hodlRestoreMsig(){
  let state=hodlMsigs[hodlActiveMsig],panel=document.getElementById("msig-card");
  if(!state){re=null;Ge=!1;hodlResetMsigForm();dr.innerHTML="";panel.hidden=!0;hodlSyncMsigClearButton();return}
  hodlSetMsigThresholds(state.fields.m||"2",state.fields.n||"3");
  let legacy=document.getElementById("msig-legacy-bip87");if(legacy)legacy.checked=Boolean(state.fields.legacyBip87);hodlSyncSelect(document.getElementById("msig-script-type"),state.fields.script||"p2wsh");hodlUpdateMsigLegacyControls();state.fields.network=state.fields.network==="testnet"?"testnet":"mainnet";hodlSyncSelect(document.getElementById("msig-network"),state.fields.network);hodlSyncSelect(document.getElementById("msig-count"),state.fields.count||"5");hodlFillKeys(state.fields.xpubs||[]);
  document.getElementById("msig-error").textContent=state.error||"";re=state.result;Ge=!1;panel.hidden=!1;
  if(re&&re.kind==="msig")hodlShowMsig();else dr.innerHTML="";hodlSyncMsigClearButton();
}
function hodlWipeActiveMsig(){
  if(hodlActiveMsig<0||!hodlMsigs[hodlActiveMsig])return;
  let state=hodlMsigs[hodlActiveMsig];hodlMsigs[hodlActiveMsig]=hodlNewMsigState(state.name,state.id,state.number);hodlRestoreMsig();
}
function hodlMsigTabKeydown(event,index){
  if(event.key==="F2"){event.preventDefault();if(index===hodlActiveMsig)hodlBeginMsigRename(index);return}
  let next=null,length=hodlMsigs.length;
  if(event.key==="ArrowRight")next=(index+1)%length;
  else if(event.key==="ArrowLeft")next=(index-1+length)%length;
  else if(event.key==="Home")next=0;
  else if(event.key==="End")next=length-1;
  if(next===null)return;
  event.preventDefault();hodlSelectMsig(next);W("#msig-tabs").children[next]?.focus();
}
function hodlCreateMsigTab(index){
  let state=hodlMsigs[index],active=index===hodlActiveMsig,button=document.createElement("button"),name=state.name||"Multisig "+state.number,label=document.createElement("span");
  button.type="button";button.id="msig-tab-"+(index+1);button.className="tab key-tab msig-tab"+(active?" active":"");button.dataset.msigNumber=String(state.number);label.className="key-tab-label";label.textContent=name;button.append(hodlCreateMsigIcon(),label);
  button.setAttribute("role","tab");button.setAttribute("aria-controls","msig-card");button.setAttribute("aria-selected",String(active));button.setAttribute("aria-label",name+(active?", selected. Activate or press F2 to rename.":". Activate to select."));button.title=active?"Click again or press F2 to rename":"Click to select";button.tabIndex=active?0:-1;
  button.onclick=()=>index===hodlActiveMsig?hodlBeginMsigRename(index):hodlSelectMsig(index);button.onkeydown=event=>hodlMsigTabKeydown(event,index);return button;
}
function hodlNormalizeMsigName(name){return String(name||"").trim().replace(/\s+/g," ").toLowerCase()}
function hodlMsigNameTaken(name,index){let normalized=hodlNormalizeMsigName(name);return!!normalized&&hodlMsigs.some((state,stateIndex)=>stateIndex!==index&&hodlNormalizeMsigName(state.name)===normalized)}
function hodlDefaultMsigName(number){let base="Multisig "+number,name=base,suffix=2;while(hodlMsigNameTaken(name,-1)){name=base+" ("+suffix+")";suffix++}return name}
function hodlBeginMsigRename(index){
  if(index!==hodlActiveMsig||!hodlMsigs[index])return;
  let box=W("#msig-tabs"),tab=box.children[index];if(!tab||tab.classList.contains("key-tab-editing"))return;
  let state=hodlMsigs[index],editor=document.createElement("div"),input=document.createElement("input"),previous=state.name||"Multisig "+state.number;
  editor.id="msig-tab-"+(index+1);editor.className="key-tab key-tab-editing msig-tab active";editor.dataset.msigNumber=String(state.number);editor.setAttribute("role","tab");editor.setAttribute("aria-selected","true");editor.setAttribute("aria-controls","msig-card");
  input.type="text";input.className="key-tab-name-input msig-tab-name-input";input.value=previous;input.maxLength=120;input.setAttribute("aria-label","Rename "+previous);input.setAttribute("aria-controls","msig-card");
  let finish=(commit,focus)=>{if(!editor.isConnected)return;let name=input.value.trim().replace(/\s+/g," ");if(commit&&name&&!hodlMsigNameTaken(name,index))state.name=name;let button=hodlCreateMsigTab(index);editor.replaceWith(button);if(focus)button.focus()};
  input.oninput=()=>hodlSizeKeyTabEditor(input);input.onkeydown=event=>{if(event.key==="Enter"){event.preventDefault();finish(!0,!0)}else if(event.key==="Escape"){event.preventDefault();finish(!1,!0)}};input.onblur=()=>finish(!0,!1);
  editor.append(hodlCreateMsigIcon(),input);tab.replaceWith(editor);hodlSizeKeyTabEditor(input);input.focus();input.select();
}
function hodlSyncMsigDeleteButton(){let button=W("#delete-msig");if(!button)return;button.disabled=hodlMsigs.length<=1;button.setAttribute("aria-disabled",String(button.disabled))}
function hodlRenderMsigTabs(){
  let box=W("#msig-tabs"),panel=W("#msig-card");box.innerHTML="";panel.removeAttribute("aria-labelledby");
  box.setAttribute("role","tablist");hodlMsigs.forEach((state,index)=>{let button=hodlCreateMsigTab(index);box.appendChild(button);if(index===hodlActiveMsig)panel.setAttribute("aria-labelledby",button.id)});hodlRevealTab(box,hodlActiveMsig);hodlSyncMsigDeleteButton();
}
function hodlSelectMsig(index){if(index===hodlActiveMsig||!hodlMsigs[index])return;hodlCaptureMsig();hodlActiveMsig=index;hodlRenderMsigTabs();hodlRestoreMsig()}
function hodlAddMsig(){hodlCaptureMsig();hodlMsigs.push(hodlNewMsigState());hodlActiveMsig=hodlMsigs.length-1;hodlRenderMsigTabs();hodlRestoreMsig()}
function hodlDeleteActiveMsig(){
  if(hodlMsigs.length<=1||hodlActiveMsig<0||!hodlMsigs[hodlActiveMsig]){hodlSyncMsigDeleteButton();return}
  let deletedIndex=hodlActiveMsig,deletedState=hodlMsigs[deletedIndex];hodlMsigs.splice(deletedIndex,1);hodlNextMsigNumber=hodlMsigs.length?hodlMsigs.reduce((latest,state)=>Math.max(latest,state.number),0)+1:deletedState.number;hodlActiveMsig=hodlMsigs.length?Math.min(deletedIndex,hodlMsigs.length-1):-1;
  hodlRenderMsigTabs();hodlRestoreMsig();(hodlActiveMsig>=0?W("#msig-tabs").children[hodlActiveMsig]:W("#add-msig"))?.focus();
}
function hodlShowWorkspace(id){
  if(id===hodlWorkspace)return;
  let preservedTop=window.scrollY,preservedLeft=window.scrollX;
  if(hodlWorkspace==="calc")hodlCaptureKey();else if(hodlWorkspace==="msig")hodlCaptureMsig();
  hodlWorkspace=id;
  [...W("#workspace").children].forEach(button=>{let active=button.dataset.workspace===id;button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active))});
  document.getElementById("key-manager").hidden=id!=="calc";
  document.getElementById("msig-manager").hidden=id!=="msig";
  document.getElementById("calc-card").hidden=!0;document.getElementById("msig-card").hidden=!0;document.getElementById("psbt-card").hidden=id!=="psbt";re=null;Ge=!1;dr.innerHTML="";
  if(id==="calc"){hodlRenderKeyTabs();hodlRestoreKey()}
  else if(id==="msig"){hodlRenderMsigTabs();hodlRestoreMsig()}
  if(hodlWorkspaceScrollFrame)cancelAnimationFrame(hodlWorkspaceScrollFrame);window.scrollTo(preservedLeft,preservedTop);hodlWorkspaceScrollFrame=requestAnimationFrame(()=>{window.scrollTo(preservedLeft,preservedTop);hodlQueueSegmentedControlSync();hodlWorkspaceScrollFrame=0});
}
function hodlInitTabDrag(box){
  let pointerId=null,startX=0,startScroll=0,moved=!1,suppressClick=!1;
  box.addEventListener("pointerdown",event=>{if(!event.isPrimary||event.button!==0||event.pointerType==="touch"||event.target.closest?.(".key-tab-editing"))return;pointerId=event.pointerId;startX=event.clientX;startScroll=box.scrollLeft;moved=!1});
  let move=event=>{if(event.pointerId!==pointerId)return;let distance=event.clientX-startX;if(!moved&&Math.abs(distance)>5){moved=!0;box.classList.add("dragging");box.setPointerCapture?.(pointerId)}if(moved){box.scrollLeft=startScroll-distance;event.preventDefault()}};
  let end=event=>{if(event.pointerId!==pointerId)return;let id=pointerId,didMove=moved;pointerId=null;moved=!1;box.classList.remove("dragging");if(box.hasPointerCapture?.(id))box.releasePointerCapture(id);if(didMove){suppressClick=!0;setTimeout(()=>{suppressClick=!1},0)}};
  window.addEventListener("pointermove",move,{passive:!1});window.addEventListener("pointerup",end);window.addEventListener("pointercancel",end);box.addEventListener("lostpointercapture",end);
  box.addEventListener("click",event=>{if(!suppressClick)return;event.preventDefault();event.stopImmediatePropagation()},!0);
  box.addEventListener("dragstart",event=>event.preventDefault());
}
function hodlInitKeyManager(){
  W("#add-key").onclick=hodlAddKey;W("#delete-key").onclick=hodlDeleteActiveKey;hodlRenderKeyTabs();hodlInitTabDrag(W("#key-tabs"));if(hodlWorkspace==="calc")hodlRestoreKey();else document.getElementById("calc-card").hidden=!0;
}
function hodlInitMsigManager(){W("#add-msig").onclick=hodlAddMsig;W("#delete-msig").onclick=hodlDeleteActiveMsig;hodlRenderMsigTabs();hodlInitTabDrag(W("#msig-tabs"));if(hodlWorkspace==="msig")hodlRestoreMsig();else document.getElementById("msig-card").hidden=!0}
function hodlSeedInitialManagers(){if(!hodlKeys.length){hodlKeys.push(hodlNewKeyState());hodlActiveKey=0}if(!hodlMsigs.length){hodlMsigs.push(hodlNewMsigState());hodlActiveMsig=0}}
function hodlInitWorkspace(){let box=W("#workspace");box.innerHTML="";[["calc","Key Derivation"],["msig","Multi Signature"],["psbt","PSBT / Nonce"]].forEach(([id,label])=>{let button=document.createElement("button"),active=hodlWorkspace===id;button.type="button";button.className="tab"+(active?" active":"");button.dataset.workspace=id;button.setAttribute("aria-pressed",String(active));button.textContent=label;button.onclick=()=>hodlShowWorkspace(id);box.appendChild(button)});hodlInitMsig();hodlInitPsbt()}
var hodlKeyClearSyncQueued=!1,hodlMsigClearSyncQueued=!1,hodlDeriveSyncQueued=!1;
function hodlQueueKeyClearButtonSync(){
  if(hodlKeyClearSyncQueued)return;hodlKeyClearSyncQueued=!0;queueMicrotask(()=>{hodlKeyClearSyncQueued=!1;hodlSyncKeyClearButton(!0)})
}
function hodlQueueMsigClearButtonSync(){
  if(hodlMsigClearSyncQueued)return;hodlMsigClearSyncQueued=!0;queueMicrotask(()=>{hodlMsigClearSyncQueued=!1;hodlSyncMsigClearButton(!0)})
}
function hodlQueueDeriveButtonSync(){
  if(hodlDeriveSyncQueued)return;hodlDeriveSyncQueued=!0;queueMicrotask(()=>{hodlDeriveSyncQueued=!1;hodlSyncDeriveButton()})
}
function hodlInitClearActionState(){
  let keyPanel=document.getElementById("calc-card"),msigPanel=document.getElementById("msig-card");
  ["input","change","click"].forEach(type=>{keyPanel.addEventListener(type,hodlQueueKeyClearButtonSync);keyPanel.addEventListener(type,hodlQueueDeriveButtonSync);msigPanel.addEventListener(type,hodlQueueMsigClearButtonSync)});
  hodlSyncKeyClearButton();hodlSyncMsigClearButton();hodlSyncDeriveButton()
}
var hodlSegmentedControlFrame=0,hodlSegmentedResizeObserver=null,hodlSegmentedControlWidths=new WeakMap();
function hodlSyncSegmentedControls(){
  hodlSegmentedControlFrame=0;
  document.querySelectorAll(".segmented-control").forEach(group=>{
    if(!group.getClientRects().length)return;
    let buttons=[...group.children].filter(child=>child.matches(".tab"));group.classList.remove("is-stacked");
    if(buttons.length<2)return;
    let firstTop=buttons[0].offsetTop,wrapped=buttons.some(button=>Math.abs(button.offsetTop-firstTop)>1);group.classList.toggle("is-stacked",wrapped)
  })
}
function hodlQueueSegmentedControlSync(){
  if(hodlSegmentedControlFrame)return;hodlSegmentedControlFrame=requestAnimationFrame(hodlSyncSegmentedControls)
}
function hodlInitSegmentedControls(){
  let groups=[...document.querySelectorAll(".segmented-control")];
  if("ResizeObserver" in window){
    hodlSegmentedResizeObserver=new ResizeObserver(entries=>{let changed=!1;entries.forEach(entry=>{let width=entry.contentRect.width,previous=hodlSegmentedControlWidths.get(entry.target);if(previous===undefined||Math.abs(previous-width)>.5){hodlSegmentedControlWidths.set(entry.target,width);changed=!0}});if(changed)hodlQueueSegmentedControlSync()});
    groups.forEach(group=>hodlSegmentedResizeObserver.observe(group))
  }
  window.addEventListener("resize",hodlQueueSegmentedControlSync,{passive:!0});hodlQueueSegmentedControlSync()
}
function hodlInitSecretFieldAutoClear(){
  let clearSecretFields=()=>{
    for(let id of["dice","hex","bin","seed","key","pass"]){let field=document.getElementById(id);if(field)field.value=""}
    hodlInvalidateActiveKeyOutput();let out=document.getElementById("out");if(out)out.innerHTML="";let error=document.getElementById("error");if(error)error.textContent=""
  };
  addEventListener("pagehide",clearSecretFields);
  addEventListener("pageshow",event=>{if(event.persisted)clearSecretFields()})
}
hodlInitWorkspace();hodlSeedInitialManagers();hodlInitKeyManager();hodlInitMsigManager();hodlInitClearActionState();hodlInitSecretFieldAutoClear();hodlInitMasterFingerprintPreview();hodlInitDerivationControls();hodlInitSegmentedControls();})();
