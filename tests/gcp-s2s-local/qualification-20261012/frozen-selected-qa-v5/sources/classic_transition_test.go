package main
import("encoding/json";"os";"testing")
func TestActual512PairedClassicTransition(t *testing.T){
 prefix:="/private/tmp/provider-gcp-cloud-expiry-observer-5121dc33-actual-measured-callbacks-v1/poststart-8cdf4b98b51a437fb7cb7626b0ac3696-guard-"
 for _,tc:=range []struct{name string;pending bool}{{"before-1",true},{"after-1",false}} {
 raw,err:=os.ReadFile(prefix+tc.name+".json");if err!=nil{t.Fatal(err)}
 var c capture;if json.Unmarshal(raw,&c)!=nil{t.Fatal("actual capture")}
 err=verifyTransitionEmpty(c)
 if (err==nil)!=tc.pending{t.Fatalf("%s pending=%v err=%v",tc.name,tc.pending,err)}
 if !tc.pending {if _,err:=verify(c,"allow","tcp");err!=nil{t.Fatal("actual restored positive proof",err)}}
 }
}
