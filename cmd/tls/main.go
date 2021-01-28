package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/cnych/admission-registry/pkg"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	// CA 配置
	subject := pkix.Name{
		Country:            []string{"CN"},
		Province:           []string{"Beijing"},
		Locality:           []string{"Beijing"},
		Organization:       []string{"ydzs.io"},
		OrganizationalUnit: []string{"ydzs.io"},
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               subject,
		NotBefore:             time.Now(), // 有效期
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true, // 根证书
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// 生成CA私钥
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 创建自签名的 CA 证书
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}

	// 编码证书文件
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		log.Panic(err)
	}

	dnsNames := []string{"admission-registry",
		"admission-registry.default",
		"admission-registry.default.svc",
		"admission-registry.default.svc.cluster.local",
	}
	commonName := "admission-registry.default.svc"
	// 服务端的证书配置
	subject.CommonName = commonName
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(2020),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// 生成服务端的私钥
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 对服务端私钥签名
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}
	serverCertPEM := new(bytes.Buffer)
	if err := pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	}); err != nil {
		log.Panic(err)
	}

	serverPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	}); err != nil {
		log.Panic(err)
	}

	// 已经生成了CA server.pem server-key.pem

	if err := os.MkdirAll("/etc/webhook/certs/", 0666); err != nil {
		log.Panic(err)
	}

	if err := pkg.WriteFile("/etc/webhook/certs/tls.crt", serverCertPEM.Bytes()); err != nil {
		log.Panic(err)
	}

	if err := pkg.WriteFile("/etc/webhook/certs/tls.key", serverPrivKeyPEM.Bytes()); err != nil {
		log.Panic(err)
	}

	log.Println("webhook server tls generated successfully")

	if err := CreateAdmissionConfig(caPEM); err != nil {
		log.Panic(err)
	}

	log.Println("webhook admission configuration object generated successfully")
}

func CreateAdmissionConfig(caCert *bytes.Buffer) error {
	clientset, err := pkg.InitKubernetesCli()
	if err != nil {
		return err
	}

	var (
		webhookNamespace, _ = os.LookupEnv("WEBHOOK_NAMESPACE")
		validateCfgName, _  = os.LookupEnv("VALIDATE_CONFIG")
		mutateCfgName, _    = os.LookupEnv("MUTATE_CONFIG")
		webhookService, _   = os.LookupEnv("WEBHOOK_SERVICE")
		validatePath, _     = os.LookupEnv("VALIDATE_PATH")
		mutatePath, _       = os.LookupEnv("MUTATE_PATH")
	)

	ctx := context.Background()
	if validateCfgName != "" {
		// 创建 ValidatingWebhookConfiguration
		validateConfig := &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: validateCfgName,
			},
			Webhooks: []admissionv1.ValidatingWebhook{
				{
					Name: "io.ydzs.admission-registry",
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admissionv1.ServiceReference{
							Name:      webhookService,
							Namespace: webhookNamespace,
							Path:      &validatePath,
						},
					},
					Rules: []admissionv1.RuleWithOperations{
						{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule: admissionv1.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"pods"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionv1.SideEffectClass {
						se := admissionv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		validateAdmissionClient := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		if _, err := validateAdmissionClient.Get(ctx, validateCfgName, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				if _, err := validateAdmissionClient.Create(ctx, validateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := validateAdmissionClient.Update(ctx, validateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	if mutateCfgName != "" {
		// 创建 MutatingWebhookConfiguration
		mutateConfig := &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: mutateCfgName,
			},
			Webhooks: []admissionv1.MutatingWebhook{
				{
					Name: "io.ydzs.admission-registry-mutate",
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admissionv1.ServiceReference{
							Name:      webhookService,
							Namespace: webhookNamespace,
							Path:      &mutatePath,
						},
					},
					Rules: []admissionv1.RuleWithOperations{
						{
							Operations: []admissionv1.OperationType{admissionv1.Create},
							Rule: admissionv1.Rule{
								APIGroups:   []string{"apps", ""},
								APIVersions: []string{"v1"},
								Resources:   []string{"deployments", "services"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionv1.SideEffectClass {
						se := admissionv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		mutateAdmissionClient := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
		if _, err := mutateAdmissionClient.Get(ctx, mutateCfgName, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				if _, err := mutateAdmissionClient.Create(ctx, mutateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := mutateAdmissionClient.Update(ctx, mutateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	return nil
}
