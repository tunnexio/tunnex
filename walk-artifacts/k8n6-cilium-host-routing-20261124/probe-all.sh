#!/bin/sh
# probe-all.sh <label>: the K8N-6 paths from the device (netns tnxdev), each read by probe.sh in the
# tools pod. HR_DIR holds kubeconfig and out/. Addresses are those of the cluster in
# docs/K8N-2-cilium.md, "Host routing — decision, 2026-11-24", "Live check".
cfg=$1; d=${HR_DIR:-.}
for t in "control: Docker network gateway|http://172.21.0.1:80/" \
         "NodePort via wg0 address|http://10.99.0.1:30080/clientip" \
         "NodePort via node primary IP|http://172.21.0.2:30080/clientip" \
         "ClusterIP web|http://10.96.59.104:80/clientip" \
         "pod IP direct web|http://10.244.0.74:8080/clientip" \
         "LoadBalancer IP|http://172.31.250.0:80/clientip" \
         "pod IP direct web2|http://10.244.0.38:8080/clientip" \
         "ClusterIP web2|http://10.96.240.142:80/clientip" \
         ${HR_EXTRA:+"$HR_EXTRA"}; do
  kubectl --kubeconfig $d/kubeconfig -n kube-system exec tools -- env LXC=${LXC:-lxc7b1be4c560fd} sh /root/probe.sh "${t%%|*}" "${t#*|}" 2>&1
done > $d/out/probe-$cfg-paths.txt
grep -E '^===|^curl: |^body' $d/out/probe-$cfg-paths.txt
grep -E '===|default_drop|trace lines' $d/out/probe-$cfg-paths.txt | awk '/===/{h=$0;n=0;next}/default_drop/{n++; if(n==2) print h" -> default_drop after: "$0; next}/trace lines/{print "   "$0}'
