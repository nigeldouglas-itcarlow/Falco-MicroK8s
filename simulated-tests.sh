# Privileged Pod (K01.01)
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/dodgy-pod.yaml
# Read-only FS Pod (K01.02)
kubectl apply -f https://raw.githubusercontent.com/nigeldouglas-itcarlow/Falco-MicroK8s/main/read-only-fs.yaml
# Run as Root User (K01.03)
kubectl apply -f https://raw.githubusercontent.com/nigel-falco/falco-talon-testing/main/RunAsRoot.yaml
