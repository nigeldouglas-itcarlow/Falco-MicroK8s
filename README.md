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
