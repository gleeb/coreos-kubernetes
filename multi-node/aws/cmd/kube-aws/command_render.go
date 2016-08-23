package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"text/template"

	"github.com/gleeb/coreos-kubernetes/multi-node/aws/pkg/config"
	"github.com/spf13/cobra"
)

var (
	cmdRender = &cobra.Command{
		Use:          "render",
		Short:        "Render a CloudFormation template",
		Long:         ``,
		RunE:         runCmdRender,
		SilenceUsage: true,
	}
)

func init() {
	cmdRoot.AddCommand(cmdRender)
}

const KubeConfigTemplateletter = `
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: credentials/ca.pem
    server: {{ .APIServerEndpoint }}
  name: kube-aws-{{ .ClusterName }}-cluster
contexts:
- context:
    cluster: kube-aws-{{ .ClusterName }}-cluster
    namespace: default
    user: kube-aws-{{ .ClusterName }}-admin
  name: kube-aws-{{ .ClusterName }}-context
users:
- name: kube-aws-{{ .ClusterName }}-admin
  user:
    client-certificate: credentials/admin.pem
    client-key: credentials/admin-key.pem
current-context: kube-aws-{{ .ClusterName }}-context
`
const CloudConfigControllerletter = `
#cloud-config
coreos:
  update:
    reboot-strategy: "off"
  flannel:
    interface: $private_ipv4
    etcd_endpoints: {{ .ETCDEndpoints }}
  etcd2:
    name: controller
    advertise-client-urls: http://$private_ipv4:2379
    initial-advertise-peer-urls: http://$private_ipv4:2380
    listen-client-urls: http://0.0.0.0:2379
    listen-peer-urls: http://0.0.0.0:2380
    initial-cluster: controller=http://$private_ipv4:2380
  units:
    - name: etcd2.service
      command: start

    - name: docker.service
      drop-ins:
        - name: 40-flannel.conf
          content: |
            [Unit]
            Requires=flanneld.service
            After=flanneld.service
            [Service]
            ExecStart=
            ExecStart=/usr/lib/coreos/dockerd daemon --host=fd:// $DOCKER_OPTS $DOCKER_CGROUPS $DOCKER_OPT_MTU

    - name: flanneld.service
      drop-ins:
        - name: 10-etcd.conf
          content: |
            [Service]
            ExecStartPre=/usr/bin/curl --silent -X PUT -d \
            "value={\"Network\" : \"{{.PodCIDR}}\", \"Backend\" : {\"Type\" : \"vxlan\"}}" \
            http://localhost:2379/v2/keys/coreos.com/network/config?prevExist=false
    - name: kubelet.service
      command: start
      enable: true
      content: |
        [Service]
        Environment=KUBELET_VERSION={{.K8sVer}}
        Environment=KUBELET_ACI={{.HyperkubeImageRepo}}
        Environment="RKT_OPTS=--volume dns,kind=host,source=/etc/resolv.conf \
        --mount volume=dns,target=/etc/resolv.conf \
        --volume=rkt,kind=host,source=/opt/bin/host-rkt \
        --mount volume=rkt,target=/usr/bin/rkt \
        --volume var-lib-rkt,kind=host,source=/var/lib/rkt \
        --mount volume=var-lib-rkt,target=/var/lib/rkt \
        --volume=stage,kind=host,source=/tmp \
        --mount volume=stage,target=/tmp"
        ExecStart=/usr/lib/coreos/kubelet-wrapper \
        --api-servers=http://localhost:8080 \
        --network-plugin-dir=/etc/kubernetes/cni/net.d \
        --network-plugin={{.K8sNetworkPlugin}} \
        --container-runtime={{.ContainerRuntime}} \
        --rkt-path=/usr/bin/rkt \
        --rkt-stage1-image=coreos.com/rkt/stage1-coreos \
        --register-schedulable=false \
        --allow-privileged=true \
        --config=/etc/kubernetes/manifests \
        --cluster_dns={{.DNSServiceIP}} \
        --cluster_domain=cluster.local \
        --cloud-provider=aws
        Restart=always
        RestartSec=10

        [Install]
        WantedBy=multi-user.target

{{ if eq .ContainerRuntime "rkt" }}
    - name: rkt-api.service
      enable: true
      content: |
        [Unit]
        Before=kubelet.service
        [Service]
        ExecStart=/usr/bin/rkt api-service
        Restart=always
        RestartSec=10
        [Install]
        RequiredBy=kubelet.service

    - name: load-rkt-stage1.service
      enable: true
      content: |
        [Unit]
        Description=Load rkt stage1 images
        Documentation=http://github.com/coreos/rkt
        Requires=network-online.target
        After=network-online.target
        Before=rkt-api.service
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/rkt fetch /usr/lib/rkt/stage1-images/stage1-coreos.aci /usr/lib/rkt/stage1-images/stage1-fly.aci  --insecure-options=image
        [Install]
        RequiredBy=rkt-api.service
{{ end }}

{{ if .UseCalico }}
    - name: calico-node.service
      command: start
      content: |
        [Unit]
        Description=Calico per-host agent
        Requires=network-online.target
        After=network-online.target

        [Service]
        Slice=machine.slice
        Environment=CALICO_DISABLE_FILE_LOGGING=true
        Environment=HOSTNAME=$private_ipv4
        Environment=IP=$private_ipv4
        Environment=FELIX_FELIXHOSTNAME=$private_ipv4
        Environment=CALICO_NETWORKING=false
        Environment=NO_DEFAULT_POOLS=true
        Environment=ETCD_ENDPOINTS={{ .ETCDEndpoints }}
        ExecStart=/usr/bin/rkt run --inherit-env --stage1-from-dir=stage1-fly.aci \
        --volume=modules,kind=host,source=/lib/modules,readOnly=false \
        --mount=volume=modules,target=/lib/modules \
        --trust-keys-from-https quay.io/calico/node:v0.19.0
        KillMode=mixed
        Restart=always
        TimeoutStartSec=0

        [Install]
        WantedBy=multi-user.target
{{ end }}

    - name: decrypt-tls-assets.service
      enable: true
      content: |
        [Unit]
        Description=decrypt kubelet tls assets using amazon kms
        Before=kubelet.service
        After=docker.service
        Requires=docker.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/opt/bin/decrypt-tls-assets

        [Install]
        RequiredBy=kubelet.service

    - name: install-kube-system.service
      command: start
      content: |
        [Unit]
        Requires=kubelet.service docker.service
        After=kubelet.service docker.service

        [Service]
        Type=simple
        StartLimitInterval=0
        Restart=on-failure
        ExecStartPre=/usr/bin/curl http://127.0.0.1:8080/version
        ExecStart=/opt/bin/install-kube-system

{{ if .UseCalico }}
    - name: install-calico-system.service
      command: start
      content: |
        [Unit]
        Requires=kubelet.service docker.service
        After=kubelet.service docker.service

        [Service]
        Type=simple
        StartLimitInterval=0
        Restart=on-failure
        ExecStartPre=/usr/bin/curl http://127.0.0.1:8080/version
        ExecStart=/opt/bin/install-calico-system
{{ end }}

write_files:
  - path: /opt/bin/install-kube-system
    permissions: 0700
    owner: root:root
    content: |
      #!/bin/bash -e
      /usr/bin/curl  -H "Content-Type: application/json" -XPOST \
      -d @"/srv/kubernetes/manifests/kube-dns-rc.json" \
      "http://127.0.0.1:8080/api/v1/namespaces/kube-system/replicationcontrollers"

      /usr/bin/curl  -H "Content-Type: application/json" -XPOST \
      -d @"/srv/kubernetes/manifests/kube-dashboard-rc.json" \
      "http://127.0.0.1:8080/api/v1/namespaces/kube-system/replicationcontrollers"

      /usr/bin/curl  -H "Content-Type: application/json" -XPOST \
      -d @"/srv/kubernetes/manifests/heapster-de.json" \
      "http://127.0.0.1:8080/apis/extensions/v1beta1/namespaces/kube-system/deployments"

      for manifest in {kube-dns,heapster,kube-dashboard}-svc.json;do
          /usr/bin/curl  -H "Content-Type: application/json" -XPOST \
          -d @"/srv/kubernetes/manifests/$manifest" \
          "http://127.0.0.1:8080/api/v1/namespaces/kube-system/services"
      done

  - path: /opt/bin/host-rkt
    permissions: 0755
    owner: root:root
    content: |
      #!/bin/sh
      # This is bind mounted into the kubelet rootfs and all rkt shell-outs go
      # through this rkt wrapper. It essentially enters the host mount namespace
      # (which it is already in) only for the purpose of breaking out of the chroot
      # before calling rkt. It makes things like rkt gc work and avoids bind mounting
      # in certain rkt filesystem dependancies into the kubelet rootfs. This can
      # eventually be obviated when the write-api stuff gets upstream and rkt gc is
      # through the api-server. Related issue:
      # https://github.com/coreos/rkt/issues/2878
      exec nsenter -m -u -i -n -p -t 1 -- /usr/bin/rkt "$@"

{{ if .UseCalico }}
  - path: /opt/bin/install-calico-system
    permissions: 0700
    owner: root:root
    content: |
      #!/bin/bash -e
      /usr/bin/curl -H "Content-Type: application/json" -XPOST -d @"/srv/kubernetes/manifests/calico-system.json" "http://127.0.0.1:8080/api/v1/namespaces"

      /usr/bin/cp /srv/kubernetes/manifests/calico-policy-controller.yaml /etc/kubernetes/manifests
{{ end }}

  - path: /opt/bin/decrypt-tls-assets
    owner: root:root
    permissions: 0700
    content: |
      #!/bin/bash -e

      for encKey in $(find /etc/kubernetes/ssl/*.pem.enc);do
        tmpPath="/tmp/$(basename $encKey).tmp"
        docker run --rm -v /etc/kubernetes/ssl:/etc/kubernetes/ssl --rm quay.io/coreos/awscli aws --region {{.Region}} kms decrypt --ciphertext-blob fileb://$encKey --output text --query Plaintext | base64 --decode > $tmpPath
        mv  $tmpPath /etc/kubernetes/ssl/$(basename $encKey .enc)
      done

  - path: /etc/kubernetes/manifests/kube-proxy.yaml
    content: |
        apiVersion: v1
        kind: Pod
        metadata:
          name: kube-proxy
          namespace: kube-system
          annotations:
            rkt.alpha.kubernetes.io/stage1-name-override: coreos.com/rkt/stage1-fly
        spec:
          hostNetwork: true
          containers:
          - name: kube-proxy
            image: {{.HyperkubeImageRepo}}:{{.K8sVer}}
            command:
            - /hyperkube
            - proxy
            - --master=http://127.0.0.1:8080
            securityContext:
              privileged: true
            volumeMounts:
            - mountPath: /etc/ssl/certs
              name: ssl-certs-host
              readOnly: true
            - mountPath: /var/run/dbus
              name: dbus
              readOnly: false
          volumes:
          - hostPath:
              path: /usr/share/ca-certificates
            name: ssl-certs-host
          - hostPath:
              path: /var/run/dbus
            name: dbus

  - path: /etc/kubernetes/manifests/kube-apiserver.yaml
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-apiserver
        namespace: kube-system
      spec:
        hostNetwork: true
        containers:
        - name: kube-apiserver
          image: {{.HyperkubeImageRepo}}:{{.K8sVer}}
          command:
          - /hyperkube
          - apiserver
          - --bind-address=0.0.0.0
          - --etcd-servers=http://localhost:2379
          - --allow-privileged=true
          - --service-cluster-ip-range={{.ServiceCIDR}}
          - --secure-port=443
          - --advertise-address=$private_ipv4
          - --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota
          - --tls-cert-file=/etc/kubernetes/ssl/apiserver.pem
          - --tls-private-key-file=/etc/kubernetes/ssl/apiserver-key.pem
          - --client-ca-file=/etc/kubernetes/ssl/ca.pem
          - --service-account-key-file=/etc/kubernetes/ssl/apiserver-key.pem
          - --runtime-config=extensions/v1beta1/networkpolicies=true
          - --cloud-provider=aws
          livenessProbe:
            httpGet:
              host: 127.0.0.1
              port: 8080
              path: /healthz
            initialDelaySeconds: 15
            timeoutSeconds: 15
          ports:
          - containerPort: 443
            hostPort: 443
            name: https
          - containerPort: 8080
            hostPort: 8080
            name: local
          volumeMounts:
          - mountPath: /etc/kubernetes/ssl
            name: ssl-certs-kubernetes
            readOnly: true
          - mountPath: /etc/ssl/certs
            name: ssl-certs-host
            readOnly: true
        volumes:
        - hostPath:
            path: /etc/kubernetes/ssl
          name: ssl-certs-kubernetes
        - hostPath:
            path: /usr/share/ca-certificates
          name: ssl-certs-host

  - path: /etc/kubernetes/manifests/kube-controller-manager.yaml
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-controller-manager
        namespace: kube-system
      spec:
        containers:
        - name: kube-controller-manager
          image: {{.HyperkubeImageRepo}}:{{.K8sVer}}
          command:
          - /hyperkube
          - controller-manager
          - --master=http://127.0.0.1:8080
          - --leader-elect=true
          - --service-account-private-key-file=/etc/kubernetes/ssl/apiserver-key.pem
          - --root-ca-file=/etc/kubernetes/ssl/ca.pem
          - --cloud-provider=aws
          resources:
            requests:
              cpu: 200m
          livenessProbe:
            httpGet:
              host: 127.0.0.1
              path: /healthz
              port: 10252
            initialDelaySeconds: 15
            timeoutSeconds: 15
          volumeMounts:
          - mountPath: /etc/kubernetes/ssl
            name: ssl-certs-kubernetes
            readOnly: true
          - mountPath: /etc/ssl/certs
            name: ssl-certs-host
            readOnly: true
        hostNetwork: true
        volumes:
        - hostPath:
            path: /etc/kubernetes/ssl
          name: ssl-certs-kubernetes
        - hostPath:
            path: /usr/share/ca-certificates
          name: ssl-certs-host

  - path: /etc/kubernetes/manifests/kube-scheduler.yaml
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-scheduler
        namespace: kube-system
      spec:
        hostNetwork: true
        containers:
        - name: kube-scheduler
          image: {{.HyperkubeImageRepo}}:{{.K8sVer}}
          command:
          - /hyperkube
          - scheduler
          - --master=http://127.0.0.1:8080
          - --leader-elect=true
          resources:
            requests:
              cpu: 100m
          livenessProbe:
            httpGet:
              host: 127.0.0.1
              path: /healthz
              port: 10251
            initialDelaySeconds: 15
            timeoutSeconds: 15

{{ if .UseCalico }}
  - path: /srv/kubernetes/manifests/calico-policy-controller.yaml
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: calico-policy-controller
        namespace: calico-system
      spec:
        hostNetwork: true
        containers:
          # The Calico policy controller.
          - name: kube-policy-controller
            image: calico/kube-policy-controller:v0.2.0
            env:
              - name: ETCD_ENDPOINTS
                value: "{{ .ETCDEndpoints }}"
              - name: K8S_API
                value: "http://127.0.0.1:8080"
              - name: LEADER_ELECTION
                value: "true"
          # Leader election container used by the policy controller.
          - name: leader-elector
            image: quay.io/calico/leader-elector:v0.1.0
            imagePullPolicy: IfNotPresent
            args:
              - "--election=calico-policy-election"
              - "--election-namespace=calico-system"
              - "--http=127.0.0.1:4040"
{{ end }}

{{ if .UseCalico }}
  - path: /srv/kubernetes/manifests/calico-system.json
    content: |
        {
          "apiVersion": "v1",
          "kind": "Namespace",
          "metadata": {
            "name": "calico-system"
          }
        }
{{ end }}

  - path: /srv/kubernetes/manifests/kube-dns-rc.json
    content: |
        {
          "apiVersion": "v1",
          "kind": "ReplicationController",
          "metadata": {
            "labels": {
              "k8s-app": "kube-dns",
              "kubernetes.io/cluster-service": "true",
              "version": "v15"
            },
            "name": "kube-dns-v15",
            "namespace": "kube-system"
          },
          "spec": {
            "replicas": 1,
            "selector": {
              "k8s-app": "kube-dns",
              "version": "v15"
            },
            "template": {
              "metadata": {
                "labels": {
                  "k8s-app": "kube-dns",
                  "kubernetes.io/cluster-service": "true",
                  "version": "v15"
                }
              },
              "spec": {
                "containers": [
                  {
                    "args": [
                      "--domain=cluster.local.",
                      "--dns-port=10053"
                    ],
                    "image": "gcr.io/google_containers/kubedns-amd64:1.3",
                    "livenessProbe": {
                      "failureThreshold": 5,
                      "httpGet": {
                        "path": "/healthz",
                        "port": 8080,
                        "scheme": "HTTP"
                      },
                      "initialDelaySeconds": 60,
                      "successThreshold": 1,
                      "timeoutSeconds": 5
                    },
                    "name": "kubedns",
                    "ports": [
                      {
                        "containerPort": 10053,
                        "name": "dns-local",
                        "protocol": "UDP"
                      },
                      {
                        "containerPort": 10053,
                        "name": "dns-tcp-local",
                        "protocol": "TCP"
                      }
                    ],
                    "readinessProbe": {
                      "httpGet": {
                        "path": "/readiness",
                        "port": 8081,
                        "scheme": "HTTP"
                      },
                      "initialDelaySeconds": 30,
                      "timeoutSeconds": 5
                    },
                    "resources": {
                      "limits": {
                        "cpu": "100m",
                        "memory": "200Mi"
                      },
                      "requests": {
                        "cpu": "100m",
                        "memory": "50Mi"
                      }
                    }
                  },
                  {
                    "args": [
                      "--cache-size=1000",
                      "--no-resolv",
                      "--server=127.0.0.1#10053"
                    ],
                    "image": "gcr.io/google_containers/kube-dnsmasq-amd64:1.3",
                    "name": "dnsmasq",
                    "ports": [
                      {
                        "containerPort": 53,
                        "name": "dns",
                        "protocol": "UDP"
                      },
                      {
                        "containerPort": 53,
                        "name": "dns-tcp",
                        "protocol": "TCP"
                      }
                    ]
                  },
                  {
                    "args": [
                      "-cmd=nslookup kubernetes.default.svc.cluster.local 127.0.0.1 >/dev/null",
                      "-port=8080",
                      "-quiet"
                    ],
                    "image": "gcr.io/google_containers/exechealthz-amd64:1.0",
                    "name": "healthz",
                    "ports": [
                      {
                        "containerPort": 8080,
                        "protocol": "TCP"
                      }
                    ],
                    "resources": {
                      "limits": {
                        "cpu": "10m",
                        "memory": "20Mi"
                      },
                      "requests": {
                        "cpu": "10m",
                        "memory": "20Mi"
                      }
                    }
                  }
                ],
                "dnsPolicy": "Default"
              }
            }
          }
        }

  - path: /srv/kubernetes/manifests/kube-dns-svc.json
    content: |
        {
          "apiVersion": "v1",
          "kind": "Service",
          "metadata": {
            "labels": {
              "k8s-app": "kube-dns",
              "kubernetes.io/cluster-service": "true",
              "kubernetes.io/name": "KubeDNS"
            },
            "name": "kube-dns",
            "namespace": "kube-system"
          },
          "spec": {
            "clusterIP": "{{.DNSServiceIP}}",
            "ports": [
              {
                "name": "dns",
                "port": 53,
                "protocol": "UDP"
              },
              {
                "name": "dns-tcp",
                "port": 53,
                "protocol": "TCP"
              }
            ],
            "selector": {
              "k8s-app": "kube-dns"
            }
          }
        }

  - path: /srv/kubernetes/manifests/heapster-de.json
    content: |
        {
          "apiVersion": "extensions/v1beta1",
          "kind": "Deployment",
          "metadata": {
            "labels": {
              "k8s-app": "heapster",
              "kubernetes.io/cluster-service": "true",
              "version": "v1.1.0"
            },
            "name": "heapster-v1.1.0",
            "namespace": "kube-system"
          },
          "spec": {
            "replicas": 1,
            "selector": {
              "matchLabels": {
                "k8s-app": "heapster",
                "version": "v1.1.0"
              }
            },
            "template": {
              "metadata": {
                "labels": {
                  "k8s-app": "heapster",
                  "version": "v1.1.0"
                }
              },
              "spec": {
                "containers": [
                  {
                    "command": [
                      "/heapster",
                      "--source=kubernetes.summary_api:''"
                    ],
                    "image": "gcr.io/google_containers/heapster:v1.1.0",
                    "name": "heapster",
                    "resources": {
                      "limits": {
                        "cpu": "100m",
                        "memory": "200Mi"
                      },
                      "requests": {
                        "cpu": "100m",
                        "memory": "200Mi"
                      }
                    }
                  },
                  {
                    "command": [
                      "/pod_nanny",
                      "--cpu=100m",
                      "--extra-cpu=0.5m",
                      "--memory=200Mi",
                      "--extra-memory=4Mi",
                      "--threshold=5",
                      "--deployment=heapster-v1.1.0",
                      "--container=heapster",
                      "--poll-period=300000",
                      "--estimator=exponential"
                    ],
                    "env": [
                      {
                        "name": "MY_POD_NAME",
                        "valueFrom": {
                          "fieldRef": {
                            "fieldPath": "metadata.name"
                          }
                        }
                      },
                      {
                        "name": "MY_POD_NAMESPACE",
                        "valueFrom": {
                          "fieldRef": {
                            "fieldPath": "metadata.namespace"
                          }
                        }
                      }
                    ],
                    "image": "gcr.io/google_containers/addon-resizer:1.3",
                    "name": "heapster-nanny",
                    "resources": {
                      "limits": {
                        "cpu": "50m",
                        "memory": "100Mi"
                      },
                      "requests": {
                        "cpu": "50m",
                        "memory": "100Mi"
                      }
                    }
                  }
                ]
              }
            }
          }
        }

  - path: /srv/kubernetes/manifests/heapster-svc.json
    content: |
        {
          "apiVersion": "v1",
          "kind": "Service",
          "metadata": {
            "labels": {
              "kubernetes.io/cluster-service": "true",
              "kubernetes.io/name": "Heapster"
            },
            "name": "heapster",
            "namespace": "kube-system"
          },
          "spec": {
            "ports": [
              {
                "port": 80,
                "targetPort": 8082
              }
            ],
            "selector": {
              "k8s-app": "heapster"
            }
          }
        }

  - path: /srv/kubernetes/manifests/kube-dashboard-rc.json
    content: |
        {
          "apiVersion": "v1",
          "kind": "ReplicationController",
          "metadata": {
            "labels": {
              "k8s-app": "kubernetes-dashboard",
              "kubernetes.io/cluster-service": "true",
              "version": "v1.1.0"
            },
            "name": "kubernetes-dashboard-v1.1.0",
            "namespace": "kube-system"
          },
          "spec": {
            "replicas": 1,
            "selector": {
              "k8s-app": "kubernetes-dashboard"
            },
            "template": {
              "metadata": {
                "labels": {
                  "k8s-app": "kubernetes-dashboard",
                  "kubernetes.io/cluster-service": "true",
                  "version": "v1.1.0"
                }
              },
              "spec": {
                "containers": [
                  {
                    "image": "gcr.io/google_containers/kubernetes-dashboard-amd64:v1.1.0",
                    "livenessProbe": {
                      "httpGet": {
                        "path": "/",
                        "port": 9090
                      },
                      "initialDelaySeconds": 30,
                      "timeoutSeconds": 30
                    },
                    "name": "kubernetes-dashboard",
                    "ports": [
                      {
                        "containerPort": 9090
                      }
                    ],
                    "resources": {
                      "limits": {
                        "cpu": "100m",
                        "memory": "50Mi"
                      },
                      "requests": {
                        "cpu": "100m",
                        "memory": "50Mi"
                      }
                    }
                  }
                ]
              }
            }
          }
        }

  - path: /srv/kubernetes/manifests/kube-dashboard-svc.json
    content: |
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "labels": {
                    "k8s-app": "kubernetes-dashboard",
                    "kubernetes.io/cluster-service": "true"
                },
                "name": "kubernetes-dashboard",
                "namespace": "kube-system"
            },
            "spec": {
                "ports": [
                    {
                        "port": 80,
                        "targetPort": 9090
                    }
                ],
                "selector": {
                    "k8s-app": "kubernetes-dashboard"
                }
            }
        }

  - path: /etc/kubernetes/ssl/ca.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.CACert}}

  - path: /etc/kubernetes/ssl/apiserver.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.APIServerCert}}

  - path: /etc/kubernetes/ssl/apiserver-key.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.APIServerKey}}

{{ if .UseCalico }}
  - path: /etc/kubernetes/cni/net.d/10-calico.conf
    content: |
        {
            "name": "calico",
            "type": "flannel",
            "delegate": {
                "type": "calico",
                "etcd_endpoints": "{{ .ETCDEndpoints }}",
                "log_level": "none",
                "log_level_stderr": "info",
                "hostname": "$private_ipv4",
                "policy": {
                    "type": "k8s",
                    "k8s_api_root": "http://127.0.0.1:8080/api/v1/"
                }
            }
        }
{{ else }}
  - path: /etc/kubernetes/cni/net.d/10-flannel.conf
    content: |
        {
            "name": "podnet",
            "type": "flannel",
            "delegate": {
                "isDefaultGateway": true
            }
        }
{{ end }}

`
const CloudConfigWorkerletter = `
#cloud-config
coreos:
  update:
    reboot-strategy: "off"
  flannel:
    interface: $private_ipv4
    etcd_endpoints: {{ .ETCDEndpoints }}
  units:
    - name: docker.service
      drop-ins:
        - name: 40-flannel.conf
          content: |
            [Unit]
            Requires=flanneld.service
            After=flanneld.service
            [Service]
            ExecStart=
            ExecStart=/usr/lib/coreos/dockerd daemon --host=fd:// $DOCKER_OPTS $DOCKER_CGROUPS $DOCKER_OPT_MTU

    - name: kubelet.service
      enable: true
      command: start
      content: |
        [Service]
        Environment=KUBELET_VERSION={{.K8sVer}}
        Environment=KUBELET_ACI={{.HyperkubeImageRepo}}
        Environment="RKT_OPTS=--volume dns,kind=host,source=/etc/resolv.conf \
        --mount volume=dns,target=/etc/resolv.conf \
        --volume=rkt,kind=host,source=/opt/bin/host-rkt \
        --mount volume=rkt,target=/usr/bin/rkt \
        --volume var-lib-rkt,kind=host,source=/var/lib/rkt \
        --mount volume=var-lib-rkt,target=/var/lib/rkt \
        --volume=stage,kind=host,source=/tmp \
        --mount volume=stage,target=/tmp"
        ExecStart=/usr/lib/coreos/kubelet-wrapper \
        --api-servers={{.SecureAPIServers}} \
        --network-plugin-dir=/etc/kubernetes/cni/net.d \
        --network-plugin={{.K8sNetworkPlugin}} \
        --container-runtime={{.ContainerRuntime}} \
        --rkt-path=/usr/bin/rkt \
        --rkt-stage1-image=coreos.com/rkt/stage1-coreos \
        --register-node=true \
        --allow-privileged=true \
        --config=/etc/kubernetes/manifests \
        --cluster_dns={{.DNSServiceIP}} \
        --cluster_domain=cluster.local \
        --cloud-provider=aws \
        --kubeconfig=/etc/kubernetes/worker-kubeconfig.yaml \
        --tls-cert-file=/etc/kubernetes/ssl/worker.pem \
        --tls-private-key-file=/etc/kubernetes/ssl/worker-key.pem
        Restart=always
        RestartSec=10
        [Install]
        WantedBy=multi-user.target

{{ if eq .ContainerRuntime "rkt" }}
    - name: rkt-api.service
      enable: true
      content: |
        [Unit]
        Before=kubelet.service
        [Service]
        ExecStart=/usr/bin/rkt api-service
        Restart=always
        RestartSec=10
        [Install]
        RequiredBy=kubelet.service

    - name: load-rkt-stage1.service
      enable: true
      content: |
        [Unit]
        Description=Load rkt stage1 images
        Documentation=http://github.com/coreos/rkt
        Requires=network-online.target
        After=network-online.target
        Before=rkt-api.service
        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/rkt fetch /usr/lib/rkt/stage1-images/stage1-coreos.aci /usr/lib/rkt/stage1-images/stage1-fly.aci  --insecure-options=image
        [Install]
        RequiredBy=rkt-api.service
{{ end }}

{{ if .UseCalico }}
    - name: calico-node.service
      command: start
      content: |
        [Unit]
        Description=Calico per-host agent
        Requires=network-online.target
        After=network-online.target

        [Service]
        Slice=machine.slice
        Environment=CALICO_DISABLE_FILE_LOGGING=true
        Environment=HOSTNAME=$private_ipv4
        Environment=IP=$private_ipv4
        Environment=FELIX_FELIXHOSTNAME=$private_ipv4
        Environment=CALICO_NETWORKING=false
        Environment=NO_DEFAULT_POOLS=true
        Environment=ETCD_ENDPOINTS={{ .ETCDEndpoints }}
        ExecStart=/usr/bin/rkt run --inherit-env --stage1-from-dir=stage1-fly.aci \
        --volume=modules,kind=host,source=/lib/modules,readOnly=false \
        --mount=volume=modules,target=/lib/modules \
        --trust-keys-from-https quay.io/calico/node:v0.19.0
        KillMode=mixed
        Restart=always
        TimeoutStartSec=0

        [Install]
        WantedBy=multi-user.target
{{ end }}

    - name: decrypt-tls-assets.service
      enable: true
      content: |
        [Unit]
        Description=decrypt kubelet tls assets using amazon kms
        Before=kubelet.service
        After=docker.service
        Requires=docker.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/opt/bin/decrypt-tls-assets

        [Install]
        RequiredBy=kubelet.service

write_files:
  - path: /opt/bin/host-rkt
    permissions: 0755
    owner: root:root
    content: |
      #!/bin/sh
      # This is bind mounted into the kubelet rootfs and all rkt shell-outs go
      # through this rkt wrapper. It essentially enters the host mount namespace
      # (which it is already in) only for the purpose of breaking out of the chroot
      # before calling rkt. It makes things like rkt gc work and avoids bind mounting
      # in certain rkt filesystem dependancies into the kubelet rootfs. This can
      # eventually be obviated when the write-api stuff gets upstream and rkt gc is
      # through the api-server. Related issue:
      # https://github.com/coreos/rkt/issues/2878
      exec nsenter -m -u -i -n -p -t 1 -- /usr/bin/rkt "$@"

  - path: /etc/kubernetes/ssl/worker.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.WorkerCert}}

  - path: /etc/kubernetes/ssl/worker-key.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.WorkerKey}}

  - path: /etc/kubernetes/ssl/ca.pem.enc
    encoding: gzip+base64
    content: {{.TLSConfig.CACert}}

  - path: /opt/bin/decrypt-tls-assets
    owner: root:root
    permissions: 0700
    content: |
      #!/bin/bash -e

      for encKey in $(find /etc/kubernetes/ssl/*.pem.enc);do
        tmpPath="/tmp/$(basename $encKey).tmp"
        docker run --rm -v /etc/kubernetes/ssl:/etc/kubernetes/ssl --rm quay.io/coreos/awscli aws --region {{.Region}} kms decrypt --ciphertext-blob fileb://$encKey --output text --query Plaintext | base64 --decode > $tmpPath
        mv  $tmpPath /etc/kubernetes/ssl/$(basename $encKey .enc)
      done

  - path: /etc/kubernetes/manifests/kube-proxy.yaml
    content: |
        apiVersion: v1
        kind: Pod
        metadata:
          name: kube-proxy
          namespace: kube-system
          annotations:
            rkt.alpha.kubernetes.io/stage1-name-override: coreos.com/rkt/stage1-fly
        spec:
          hostNetwork: true
          containers:
          - name: kube-proxy
            image: {{.HyperkubeImageRepo}}:{{.K8sVer}}
            command:
            - /hyperkube
            - proxy
            - --master=https://{{.ControllerIP}}:443
            - --kubeconfig=/etc/kubernetes/worker-kubeconfig.yaml
            securityContext:
              privileged: true
            volumeMounts:
              - mountPath: /etc/ssl/certs
                name: "ssl-certs"
              - mountPath: /etc/kubernetes/worker-kubeconfig.yaml
                name: "kubeconfig"
                readOnly: true
              - mountPath: /etc/kubernetes/ssl
                name: "etc-kube-ssl"
                readOnly: true
              - mountPath: /var/run/dbus
                name: dbus
                readOnly: false
          volumes:
            - name: "ssl-certs"
              hostPath:
                path: "/usr/share/ca-certificates"
            - name: "kubeconfig"
              hostPath:
                path: "/etc/kubernetes/worker-kubeconfig.yaml"
            - name: "etc-kube-ssl"
              hostPath:
                path: "/etc/kubernetes/ssl"
            - hostPath:
                path: /var/run/dbus
              name: dbus

  - path: /etc/kubernetes/worker-kubeconfig.yaml
    content: |
        apiVersion: v1
        kind: Config
        clusters:
        - name: local
          cluster:
            certificate-authority: /etc/kubernetes/ssl/ca.pem
        users:
        - name: kubelet
          user:
            client-certificate: /etc/kubernetes/ssl/worker.pem
            client-key: /etc/kubernetes/ssl/worker-key.pem
        contexts:
        - context:
            cluster: local
            user: kubelet
          name: kubelet-context
        current-context: kubelet-context

{{ if .UseCalico }}
  - path: /etc/kubernetes/cni/net.d/10-calico.conf
    content: |
        {
            "name": "calico",
            "type": "flannel",
            "delegate": {
                "type": "calico",
                "etcd_endpoints": "{{ .ETCDEndpoints }}",
                "log_level": "none",
                "log_level_stderr": "info",
                "hostname": "$private_ipv4",
                "policy": {
                    "type": "k8s",
                    "k8s_api_root": "https://{{.ControllerIP}}:443/api/v1/",
                    "k8s_client_key": "/etc/kubernetes/ssl/worker-key.pem",
                    "k8s_client_certificate": "/etc/kubernetes/ssl/worker.pem"
                }
            }
        }
{{ else }}
  - path: /etc/kubernetes/cni/net.d/10-flannel.conf
    content: |
        {
            "name": "podnet",
            "type": "flannel",
            "delegate": {
                "isDefaultGateway": true
            }
        }
{{ end }}

`
const StackTemplateTemplateletter = `
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "kube-aws Kubernetes cluster {{.ClusterName}}",
  "Resources": {
    "AlarmControllerRecover": {
      "Properties": {
        "AlarmActions": [
          {
            "Fn::Join": [
              "",
              [
                "arn:aws:automate:",
                {
                  "Ref": "AWS::Region"
                },
                ":ec2:recover"
              ]
            ]
          }
        ],
        "AlarmDescription": "Trigger a recovery when system check fails for 5 consecutive minutes.",
        "ComparisonOperator": "GreaterThanThreshold",
        "Dimensions": [
          {
            "Name": "InstanceId",
            "Value": {
              "Ref": "InstanceController"
            }
          }
        ],
        "EvaluationPeriods": "5",
        "MetricName": "StatusCheckFailed_System",
        "Namespace": "AWS/EC2",
        "Period": "60",
        "Statistic": "Minimum",
        "Threshold": "0"
      },
      "Type": "AWS::CloudWatch::Alarm"
    },
    "AutoScaleWorker": {
      "Properties": {
        "AvailabilityZones": [
          {{range $index, $subnet := .Subnets}}
          {{if gt $index 0}},{{end}}
          "{{$subnet.AvailabilityZone}}"
          {{end}}
        ],
        "DesiredCapacity": "{{.WorkerCount}}",
        "HealthCheckGracePeriod": 600,
        "HealthCheckType": "EC2",
        "LaunchConfigurationName": {
          "Ref": "LaunchConfigurationWorker"
        },
        "MaxSize": "{{.WorkerCount}}",
        "MinSize": "{{.WorkerCount}}",
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "PropagateAtLaunch": "true",
            "Value": "{{.ClusterName}}"
          },
          {
            "Key": "Name",
            "PropagateAtLaunch": "true",
            "Value": "{{.ClusterName}}-kube-aws-worker"
          }
        ],
        "VPCZoneIdentifier": [
          {{range $index, $subnet := .Subnets}}
          {{with $subnetLogicalName := printf "Subnet%d" $index}}
          {{if gt $index 0}},{{end}}
          {
            "Ref": "{{$subnetLogicalName}}"
          }
          {{end}}
          {{end}}
        ]
      },
      "Type": "AWS::AutoScaling::AutoScalingGroup",
      "UpdatePolicy" : {
        "AutoScalingRollingUpdate" : {
          "MinInstancesInService" :
          {{if .WorkerSpotPrice}}
          "0"
          {{else}}
          "{{.WorkerCount}}"
          {{end}},
          "MaxBatchSize" : "1",
          "PauseTime" : "PT2M"
        }
      }
    },
    "EIPController": {
      "Properties": {
        "Domain": "vpc",
        "InstanceId": {
          "Ref": "InstanceController"
        }
      },
      "Type": "AWS::EC2::EIP"
    },
    {{ if .CreateRecordSet }}
    "ExternalDNS": {
      "Type": "AWS::Route53::RecordSet",
      "Properties": {
	{{ if .HostedZoneID }}
        "HostedZoneId": "{{.HostedZoneID}}",
	{{else}}
        "HostedZoneName": "{{.HostedZone}}",
	{{ end }}
        "Name": "{{.ExternalDNSName}}",
        "TTL": {{.RecordSetTTL}},
        "ResourceRecords": [{ "Ref": "EIPController"}],
        "Type": "A"
      }
    },
    {{ end }}
    "IAMInstanceProfileController": {
      "Properties": {
        "Path": "/",
        "Roles": [
          {
            "Ref": "IAMRoleController"
          }
        ]
      },
      "Type": "AWS::IAM::InstanceProfile"
    },
    "IAMInstanceProfileWorker": {
      "Properties": {
        "Path": "/",
        "Roles": [
          {
            "Ref": "IAMRoleWorker"
          }
        ]
      },
      "Type": "AWS::IAM::InstanceProfile"
    },
    "IAMRoleController": {
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Action": [
                "sts:AssumeRole"
              ],
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "ec2.amazonaws.com"
                ]
              }
            }
          ],
          "Version": "2012-10-17"
        },
        "Path": "/",
        "Policies": [
          {
            "PolicyDocument": {
              "Statement": [
                {
                  "Action": "ec2:*",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action": "elasticloadbalancing:*",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action" : "kms:Decrypt",
                  "Effect" : "Allow",
                  "Resource" : "{{.KMSKeyARN}}"
                }
              ],
              "Version": "2012-10-17"
            },
            "PolicyName": "root"
          }
        ]
      },
      "Type": "AWS::IAM::Role"
    },
    "IAMRoleWorker": {
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Statement": [
            {
              "Action": [
                "sts:AssumeRole"
              ],
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "ec2.amazonaws.com"
                ]
              }
            }
          ],
          "Version": "2012-10-17"
        },
        "Path": "/",
        "Policies": [
          {
            "PolicyDocument": {
              "Statement": [
                {
                  "Action": "ec2:Describe*",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action": "ec2:AttachVolume",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action": "ec2:DetachVolume",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                {
                  "Action" : "kms:Decrypt",
                  "Effect" : "Allow",
                  "Resource" : "{{.KMSKeyARN}}"
                },
                {
                  "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetRepositoryPolicy",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                    "ecr:BatchGetImage"
                  ],
                  "Resource": "*",
                  "Effect": "Allow"
                }
              ],
              "Version": "2012-10-17"
            },
            "PolicyName": "root"
          }
        ]
      },
      "Type": "AWS::IAM::Role"
    },
    "InstanceController": {
      "Properties": {
        "AvailabilityZone": "{{(index .Subnets .ControllerSubnetIndex).AvailabilityZone}}",
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/xvda",
            "Ebs": {
              "VolumeSize": "{{.ControllerRootVolumeSize}}",
              {{if gt .ControllerRootVolumeIOPS 0}}
              "Iops": "{{.ControllerRootVolumeIOPS}}",
              {{end}}
              "VolumeType": "{{.ControllerRootVolumeType}}"
            }
          }
        ],
        "IamInstanceProfile": {
          "Ref": "IAMInstanceProfileController"
        },
        "ImageId": "{{.AMI}}",
        "InstanceType": "{{.ControllerInstanceType}}",
        "KeyName": "{{.KeyName}}",
        "NetworkInterfaces": [
          {
            "AssociatePublicIpAddress": false,
            "DeleteOnTermination": true,
            "DeviceIndex": "0",
            "GroupSet": [
              {
                "Ref": "SecurityGroupController"
              }
            ],
            "PrivateIpAddress": "{{.ControllerIP}}",
            "SubnetId": {
              "Ref": "Subnet{{.ControllerSubnetIndex}}"
            }
          }
        ],
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          },
          {
            "Key": "Name",
            "Value": "{{.ClusterName}}-kube-aws-controller"
          }
        ],
        "UserData": "{{ .UserDataController }}"
      },
      "Type": "AWS::EC2::Instance"
    },
    "LaunchConfigurationWorker": {
      "Properties": {
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/xvda",
            "Ebs": {
              "VolumeSize": "{{.WorkerRootVolumeSize}}",
              {{if gt .WorkerRootVolumeIOPS 0}}
              "Iops": "{{.WorkerRootVolumeIOPS}}",
              {{end}}
              "VolumeType": "{{.WorkerRootVolumeType}}"
            }
          }
        ],
        "IamInstanceProfile": {
          "Ref": "IAMInstanceProfileWorker"
        },
        "ImageId": "{{.AMI}}",
        "InstanceType": "{{.WorkerInstanceType}}",
        "KeyName": "{{.KeyName}}",
        "SecurityGroups": [
          {
            "Ref": "SecurityGroupWorker"
          }
        ],
        {{if .WorkerSpotPrice}}
        "SpotPrice": {{.WorkerSpotPrice}},
        {{end}}
        "UserData": "{{ .UserDataWorker }}"
      },
      "Type": "AWS::AutoScaling::LaunchConfiguration"
    },
    "SecurityGroupController": {
      "Properties": {
        "GroupDescription": {
          "Ref": "AWS::StackName"
        },
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": -1,
            "IpProtocol": "icmp",
            "ToPort": -1
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 0,
            "IpProtocol": "tcp",
            "ToPort": 65535
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 0,
            "IpProtocol": "udp",
            "ToPort": 65535
          }
        ],
        "SecurityGroupIngress": [
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": -1,
            "IpProtocol": "icmp",
            "ToPort": -1
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 22,
            "IpProtocol": "tcp",
            "ToPort": 22
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 443,
            "IpProtocol": "tcp",
            "ToPort": 443
          }
        ],
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          }
        ],
        "VpcId": {{.VPCRef}}
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "SecurityGroupControllerIngressFromWorkerToEtcd": {
      "Properties": {
        "FromPort": 2379,
        "GroupId": {
          "Ref": "SecurityGroupController"
        },
        "IpProtocol": "tcp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "ToPort": 2379
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorker": {
      "Properties": {
        "GroupDescription": {
          "Ref": "AWS::StackName"
        },
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": -1,
            "IpProtocol": "icmp",
            "ToPort": -1
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 0,
            "IpProtocol": "tcp",
            "ToPort": 65535
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 0,
            "IpProtocol": "udp",
            "ToPort": 65535
          }
        ],
        "SecurityGroupIngress": [
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": -1,
            "IpProtocol": "icmp",
            "ToPort": -1
          },
          {
            "CidrIp": "0.0.0.0/0",
            "FromPort": 22,
            "IpProtocol": "tcp",
            "ToPort": 22
          }
        ],
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          }
        ],
        "VpcId": {{.VPCRef}}
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "SecurityGroupWorkerIngressFromControllerToFlannel": {
      "Properties": {
        "FromPort": 8472,
        "GroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "IpProtocol": "udp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupController"
        },
        "ToPort": 8472
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromFlannelToController": {
      "Properties": {
        "FromPort": 8472,
        "GroupId": {
          "Ref": "SecurityGroupController"
        },
        "IpProtocol": "udp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "ToPort": 8472
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromControllerToKubelet": {
      "Properties": {
        "FromPort": 10250,
        "GroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "IpProtocol": "tcp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupController"
        },
        "ToPort": 10250
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromControllerTocAdvisor": {
      "Properties": {
        "FromPort": 4194,
        "GroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "IpProtocol": "tcp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupController"
        },
        "ToPort": 4194
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromWorkerToFlannel": {
      "Properties": {
        "FromPort": 8472,
        "GroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "IpProtocol": "udp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "ToPort": 8472
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromWorkerToWorkerKubeletReadOnly": {
      "Properties": {
        "FromPort": 10255,
        "GroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "IpProtocol": "tcp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "ToPort": 10255
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    },
    "SecurityGroupWorkerIngressFromWorkerToControllerKubeletReadOnly": {
      "Properties": {
        "FromPort": 10255,
        "GroupId": {
          "Ref": "SecurityGroupController"
        },
        "IpProtocol": "tcp",
        "SourceSecurityGroupId": {
          "Ref": "SecurityGroupWorker"
        },
        "ToPort": 10255
      },
      "Type": "AWS::EC2::SecurityGroupIngress"
    }
    {{range $index, $subnet := .Subnets}}
    {{with $subnetLogicalName := printf "Subnet%d" $index}}
    ,
    "{{$subnetLogicalName}}": {
      "Properties": {
        "AvailabilityZone": "{{$subnet.AvailabilityZone}}",
        "CidrBlock": "{{$subnet.InstanceCIDR}}",
        "MapPublicIpOnLaunch": true,
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{$.ClusterName}}"
          }
        ],
        "VpcId": {{$.VPCRef}}
      },
      "Type": "AWS::EC2::Subnet"
    }
    {{end}}
    {{end}}
    {{if not .VPCID}}
    ,
    "{{.VPCLogicalName}}": {
      "Properties": {
        "CidrBlock": "{{.VPCCIDR}}",
        "EnableDnsHostnames": true,
        "EnableDnsSupport": true,
        "InstanceTenancy": "default",
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          },
          {
            "Key": "Name",
            "Value": "kubernetes-{{.ClusterName}}-vpc"
          }
        ]
      },
      "Type": "AWS::EC2::VPC"
    },
    "RouteTable": {
      "Properties": {
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          }
        ],
        "VpcId": {{.VPCRef}}
      },
      "Type": "AWS::EC2::RouteTable"
    },
    "RouteToInternet": {
      "Properties": {
        "DestinationCidrBlock": "0.0.0.0/0",
        "GatewayId": {
          "Ref": "InternetGateway"
        },
        "RouteTableId": { "Ref" : "RouteTable" }
      },
      "Type": "AWS::EC2::Route"
    },
    "InternetGateway": {
      "Properties": {
        "Tags": [
          {
            "Key": "KubernetesCluster",
            "Value": "{{.ClusterName}}"
          }
        ]
      },
      "Type": "AWS::EC2::InternetGateway"
    },
    "VPCGatewayAttachment": {
      "Properties": {
        "InternetGatewayId": {
          "Ref": "InternetGateway"
        },
        "VpcId": {{.VPCRef}}
      },
      "Type": "AWS::EC2::VPCGatewayAttachment"
    }
    {{range $index, $subnet := .Subnets}}
    {{with $subnetLogicalName := printf "Subnet%d" $index}}
    ,
    "{{$subnetLogicalName}}RouteTableAssociation": {
      "Properties": {
        "RouteTableId": { "Ref" : "RouteTable"},
        "SubnetId": {
          "Ref": "{{$subnetLogicalName}}"
        }
      },
      "Type": "AWS::EC2::SubnetRouteTableAssociation"
    }
    {{end}}
    {{end}}
    {{else}}
    {{if .RouteTableID}}
    {{range $index, $subnet := .Subnets}}
    {{with $subnetLogicalName := printf "Subnet%d" $index}}
    ,
    "{{$subnetLogicalName}}RouteTableAssociation": {
      "Properties": {
        "RouteTableId": "{{$.RouteTableID}}",
        "SubnetId": {
          "Ref": "{{$subnetLogicalName}}"
        }
      },
      "Type": "AWS::EC2::SubnetRouteTableAssociation"
    }
    {{end}}
    {{end}}
    {{end}}
    {{end}}

  }
}

`

func runCmdRender(cmd *cobra.Command, args []string) error {
	// Read the config from file.
	cluster, err := config.ClusterFromFile(configPath)
	if err != nil {
		return fmt.Errorf("Failed to read cluster config: %v", err)
	}

	// Generate default TLS assets.
	assets, err := cluster.NewTLSAssets()
	if err != nil {
		return fmt.Errorf("Error generating default assets: %v", err)
	}
	if err := os.Mkdir("credentials", 0700); err != nil {
		return err
	}
	if err := assets.WriteToDir("./credentials"); err != nil {
		return fmt.Errorf("Error create assets: %v", err)
	}

	// Create a Config and attempt to render a kubeconfig for it.
	cfg, err := cluster.Config()
	if err != nil {
		return fmt.Errorf("Failed to create config: %v", err)
	}
	tmpl, err := template.New("kubeconfig.yaml").Parse(KubeConfigTemplateletter)
	if err != nil {
		return fmt.Errorf("Failed to parse default kubeconfig template: %v", err)
	}
	var kubeconfig bytes.Buffer
	if err := tmpl.Execute(&kubeconfig, cfg); err != nil {
		return fmt.Errorf("Failed to render kubeconfig: %v", err)
	}

	// Write all assets to disk.
	userdataDir := "userdata"
	if err := os.Mkdir(userdataDir, 0755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"credentials/.gitignore", []byte("*"), 0644},
		{"userdata/cloud-config-controller", []byte(CloudConfigControllerletter), 0644},
		{"userdata/cloud-config-worker", []byte(CloudConfigWorkerletter), 0644},
		{"stack-template.json", []byte(StackTemplateTemplateletter), 0644},
		{"kubeconfig", kubeconfig.Bytes(), 0600},
	}
	for _, file := range files {
		if err := ioutil.WriteFile(file.name, file.data, file.mode); err != nil {
			return err
		}
	}

	successMsg :=
		`Success! Stack rendered to stack-template.json.

Next steps:
1. (Optional) Validate your changes to %s with "kube-aws validate"
2. (Optional) Further customize the cluster by modifying stack-template.json or files in ./userdata.
3. Start the cluster with "kube-aws up".
`

	fmt.Printf(successMsg, configPath)
	return nil
}
