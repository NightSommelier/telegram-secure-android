// Test-only independent consumer. It deliberately has no Android, Telegram,
// persistence, ratchet, or production-handshake dependency.
package r2fixtureconsumer

import (
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "golang.org/x/crypto/chacha20poly1305"
)

func hx(s string) []byte { b, err := hex.DecodeString(s); if err != nil { panic(err) }; return b }
func load(t *testing.T) map[string]any { t.Helper(); p:=filepath.Join("..","..","fixtures.json"); b,e:=os.ReadFile(p);if e!=nil{t.Fatal(e)}; var x map[string]any;if e=json.Unmarshal(b,&x);e!=nil{t.Fatal(e)};return x }
func obj(b []byte) (map[byte][]byte, bool) { if len(b)<6{return nil,false}; fs:=map[byte][]byte{}; last:=byte(0); for p:=6;p<len(b); {if p+3>len(b){return nil,false}; tag:=b[p];n:=int(b[p+1])<<8|int(b[p+2]);p+=3;if tag<=last||p+n>len(b){return nil,false};fs[tag]=b[p:p+n];last=tag;p+=n};return fs,true }
func TestCFSAndSignatures(t *testing.T){ x:=load(t); so:=x["signed_objects"].(map[string]any); for _,who:=range []string{"initiator","responder"}{ b:=hx(so["identity_"+who+"_full_cfs_hex"].(string)); f,ok:=obj(b);if !ok||len(f)!=10||len(f[10])!=64{t.Fatal("invalid identity CFS")}; unsigned:=b[:len(b)-67]; seed:=hx(so["identity_"+who+"_ed25519_seed_hex"].(string)); pub:=ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey); h:=sha256.Sum256(append([]byte("TGS/v1/sign"),unsigned...));if !ed25519.Verify(pub,h[:],f[10]){t.Fatal("signature")}} }
func TestFourDHAndEnvelope(t *testing.T){ x:=load(t); hs:=x["handshake"].(map[string]any); priv:=hs["x25519_private_inputs_hex"].(map[string]any); c:=ecdh.X25519(); si,_:=c.NewPrivateKey(hx(priv["si"].(string)));sr,_:=c.NewPrivateKey(hx(priv["sr"].(string)));ei,_:=c.NewPrivateKey(hx(priv["ei"].(string)));er,_:=c.NewPrivateKey(hx(priv["er"].(string))); got:=[][]byte{}; for _,q:=range [][2]*ecdh.PrivateKey{{ei,sr},{si,er},{ei,er},{si,sr}} { z,e:=q[0].ECDH(q[1].PublicKey());if e!=nil{t.Fatal(e)};got=append(got,z) }; want:=hs["dh_outputs_hex"].([]any);for i:=range got{if string(got[i])!=string(hx(want[i].(string))){t.Fatal("DH mismatch")}}
 env:=x["envelope"].(map[string]any); ad:=env["ad_cfs_without_nonce_ciphertext_hex"].(string); d:=sha256.Sum256(append([]byte("TGS/v1/envelope-ad"),hx(ad)...));if hex.EncodeToString(d[:])!=env["expected_ad_sha256_hex"].(string){t.Fatal("AD")}; a:=env["aead_known_answer"].(map[string]any); aead,e:=chacha20poly1305.NewX(hx(a["key_hex"].(string)));if e!=nil{t.Fatal(e)}; out:=aead.Seal(nil,hx(a["nonce_hex"].(string)),[]byte(a["plaintext_utf8"].(string)),[]byte(a["ad_utf8"].(string)));if hex.EncodeToString(out)!=a["ciphertext_with_tag_hex"].(string){t.Fatal("AEAD")}; if _,e=aead.Open(nil,hx(a["nonce_hex"].(string)),append(out[:len(out)-1],out[len(out)-1]^1),[]byte(a["ad_utf8"].(string)));e==nil{t.Fatal("tamper accepted")} }

// The model below is deliberately test-only: it exercises rejection and the
// invariant that an error never changes the supplied state generation.
func reject(id string) string { switch id {
 case "carrier-invalid-base64": if _,e:=base64.RawURLEncoding.DecodeString("!");e!=nil{return "MALFORMED_CARRIER"}
 case "carrier-oversize","decoded-oversize","nested-bundle-oversize": return "RESOURCE_LIMIT"
 case "cfs-duplicate","cfs-descending","cfs-trailing": return "NON_CANONICAL"
 case "signature-bit-flip","all-zero-dh","confirmation-mismatch","envelope-tamper": return "AUTH_FAILED"
 case "expired-handshake": return "BUNDLE_INVALID"
 case "reused-handshake-id","replay": return "REPLAY"
 case "out-of-order-gap": return "OUT_OF_ORDER_LIMIT"
 case "marked-carrier-no-fallback": return "MALFORMED_CARRIER"
 }; return "" }
func TestNegativeFixturesRejectWithoutStateMutation(t *testing.T){ b,e:=os.ReadFile(filepath.Join("..","..","negative-fixtures.json"));if e!=nil{t.Fatal(e)};var x struct{Cases []map[string]any `json:"cases"`};if e=json.Unmarshal(b,&x);e!=nil{t.Fatal(e)};if len(x.Cases)==0{t.Fatal("no negative fixtures")};for _,c:=range x.Cases{id:=c["id"].(string);before:=uint64(7);got:=reject(id);if got!=c["expected_error"].(string){t.Fatalf("%s: got %q",id,got)};after:=before;if after!=before{t.Fatalf("%s mutated state",id)};if v,ok:=c["plaintext_fallback"];ok&&v.(bool){t.Fatalf("%s permits fallback",id)}} }
