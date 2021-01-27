package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/cnych/admission-registry/pkg"
	log "github.com/sirupsen/logrus"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	var caPEM, serverCertPEM, serverPrivKeyPEM *bytes.Buffer
	// CA config
	subject := pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{"ydzs.io"},
		OrganizationalUnit: []string{"ydzs.io"},
		Province:           []string{"Beijing"},
		Locality:           []string{"Beijing"},
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021), // SerialNumber 是 CA 颁布的唯一序列号
		Subject:      subject,
		NotBefore:    time.Now(), // 有效期限
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true, // 根证书
		// 密钥扩展用途的序列(客户端认证和数据加密)
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsage 与 ExtKeyUsage 用来表明该证书是用来做服务器认证的
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true, // 基本的有效性约束
	}

	// 生成 CA 私钥
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 创建自签名的 CA 证书（第二个和第三个参数相同，则证书是自签名的）
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}

	// 编码证书文件和私钥文件
	caPEM = new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	dnsNames := []string{"admission-registry",
		"admission-registry.default", "admission-registry.default.svc"}
	commonName := "admission-registry.default.svc"

	// 服务端证书配置
	subject.CommonName = commonName
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1658),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// 生成服务端的私钥
	serverPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 对服务端私钥签名
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}

	// 编码服务端证书和私钥
	serverCertPEM = new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	err = os.MkdirAll("/etc/webhook/certs/", 0666)
	if err != nil {
		log.Panic(err)
	}

	err = pkg.WriteFile("/etc/webhook/certs/tls.crt", serverCertPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	err = pkg.WriteFile("/etc/webhook/certs/tls.key", serverPrivKeyPEM.Bytes())
	if err != nil {
		log.Panic(err)
	}

	log.Info("Webhook tls certificates generate successfully")

	err = CreateAdmissionConfig(caPEM)
	if err != nil {
		log.Panic(err)
	}

	log.Info("Webhook configuration object generate successfully")

}

func CreateAdmissionConfig(caCert *bytes.Buffer) error {
	var (
		webhookNamespace, _ = os.LookupEnv("WEBHOOK_NAMESPACE")
		mutationCfgName, _  = os.LookupEnv("MUTATE_CONFIG")
		validateCfgName, _  = os.LookupEnv("VALIDATE_CONFIG")
		webhookService, _   = os.LookupEnv("WEBHOOK_SERVICE")
		validatePath, _     = os.LookupEnv("VALIDATE_PATH")
		mutationPath, _     = os.LookupEnv("MUTATE_PATH")
	)

	clientset, err := pkg.InitKubernetesCli()
	if err != nil {
		return err
	}

	ctx := context.Background()

	if validateCfgName != "" {
		validateConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: validateCfgName,
			},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name: "io.ydzs.admission-registry",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admissionregistrationv1.ServiceReference{
							Name:      webhookService,
							Namespace: webhookNamespace,
							Path:      &validatePath,
						},
					},
					Rules: []admissionregistrationv1.RuleWithOperations{
						{
							Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
							Rule: admissionregistrationv1.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"pods"},
							},
						},
					},
					FailurePolicy: func() *admissionregistrationv1.FailurePolicyType {
						pt := admissionregistrationv1.Fail
						return &pt
					}(),
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admissionregistrationv1.SideEffectClass {
						se := admissionregistrationv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}

		validateAdmissionClient := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		_, err := validateAdmissionClient.Get(ctx, validateCfgName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				if _, err = validateAdmissionClient.Create(ctx, validateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err = validateAdmissionClient.Update(ctx, validateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}

	}

	if mutationCfgName != "" {
		mutateConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: mutationCfgName,
			},
			Webhooks: []admissionregistrationv1.MutatingWebhook{{
				Name: "io.ydzs.admission-registry-mutate",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: caCert.Bytes(), // CA bundle created earlier
					Service: &admissionregistrationv1.ServiceReference{
						Name:      webhookService,
						Namespace: webhookNamespace,
						Path:      &mutationPath,
					},
				},
				Rules: []admissionregistrationv1.RuleWithOperations{{Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"apps", ""},
						APIVersions: []string{"v1"},
						Resources:   []string{"deployments", "services"},
					},
				}},
				FailurePolicy: func() *admissionregistrationv1.FailurePolicyType {
					pt := admissionregistrationv1.Fail
					return &pt
				}(),
				AdmissionReviewVersions: []string{"v1"},
				SideEffects: func() *admissionregistrationv1.SideEffectClass {
					se := admissionregistrationv1.SideEffectClassNone
					return &se
				}(),
			}},
		}

		mutateAdmissionClient := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
		_, err := mutateAdmissionClient.Get(ctx, mutationCfgName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				if _, err = mutateAdmissionClient.Create(ctx, mutateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err = mutateAdmissionClient.Update(ctx, mutateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}

	}

	return nil
}
