// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package log connects and observes telemetry from KubeArmor
package log

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/kubearmor/kubearmor-client/cert"
	"google.golang.org/grpc/credentials"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

var (
	KubeArmorCALabels = map[string]string{
		"kubearmor-app": "kubearmor-ca",
	}
)

func getKubeArmorCaSecret(client kubernetes.Interface) (string, string) {
	secret, err := client.CoreV1().Secrets("").List(context.Background(), v1.ListOptions{
		LabelSelector: v1.FormatLabelSelector(&v1.LabelSelector{MatchLabels: KubeArmorCALabels}),
	})
	if err != nil {
		klog.Errorf("error getting kubearmor ca secret: %v", err)
		return "", ""
	}
	if len(secret.Items) < 1 {
		klog.Errorf("no kubearmor ca secret found in the cluster: %v", err)
		return "", ""
	}
	return secret.Items[0].Name, secret.Items[0].Namespace
}

func loadTLSCredentials(client kubernetes.Interface, o Options) (credentials.TransportCredentials, error) {
	var secret, namespace string
	if o.ReadCAFromSecret {
		secret, namespace = getKubeArmorCaSecret(client)
		if secret == "" || namespace == "" {
			return credentials.NewTLS(&tls.Config{}), fmt.Errorf("error getting kubearmor ca secret")
		}
	}
	// create certificate configurations
	clientCertConfig := cert.DefaultKubeArmorClientConfig
	clientCertConfig.NotAfter = time.Now().Add(365 * 24 * time.Hour) //valid for 1 year
	// as of now daemonset creates certificates dynamically
	tlsConfig := cert.TlsConfig{
		CertCfg:              clientCertConfig,
		ReadCACertFromSecret: o.ReadCAFromSecret,
		Secret:               secret,
		Namespace:            namespace,
		K8sClient:            client.(*kubernetes.Clientset),
		CertPath:             cert.GetClientCertPath(o.TlsCertPath),
		CertProvider:         o.TlsCertProvider,
		CACertPath:           cert.GetCACertPath(o.TlsCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsClientCredentials()
	if err != nil {
		fmt.Println(err.Error())
	}
	return creds, err
}
