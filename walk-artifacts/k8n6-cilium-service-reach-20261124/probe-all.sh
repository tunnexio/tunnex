cfg=$1
for t in "NodePort via wg0 address|http://10.99.0.1:30080/clientip" "NodePort via node primary IP|http://172.21.0.2:30080/clientip" "ClusterIP|http://10.96.229.86:80/clientip" "pod IP direct|http://10.244.0.35:8080/clientip" "LoadBalancer IP|http://172.31.250.0:80/clientip"; do
  docker exec k8n-f10-tools sh /root/probe.sh "${t%%|*}" "${t#*|}" 2>&1; done > ${F10_DIR:-.}/out/probe-$cfg-paths.txt
grep -E '^===|^curl: (http|curl)|^body|default_drop|trace lines|^000|Flags \[S\]' ${F10_DIR:-.}/out/probe-$cfg-paths.txt | grep -v 'counter packets' ; echo; grep -E '===|default_drop' ${F10_DIR:-.}/out/probe-$cfg-paths.txt | sed -n '1,200p' | awk '/===/{h=$0;n=0;next}{n++; if(n==2) print h" -> after:"$0}'
