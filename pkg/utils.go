package pkg

import (
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// WriteFile writes data in the file at the given path
func WriteFile(filepath string, bytes []byte) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func InitKubernetesCli() (*kubernetes.Clientset, error) {
	var (
		err    error
		config *rest.Config
	)
	if config, err = rest.InClusterConfig(); err != nil {
		return nil, err
	}
	// 创建 Clientset 对象
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
