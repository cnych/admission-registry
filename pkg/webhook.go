package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	admissionV1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog"
)

var (
	runtimeScheme = runtime.NewScheme()
	codeFactory = serializer.NewCodecFactory(runtimeScheme)
	deserializer = codeFactory.UniversalDeserializer()
)

type WhSvrParam struct {
	Port int
	CertFile string
	KeyFile string
}

type WebhookServer struct {
	Server *http.Server   // http server
	WhiteListRegistries []string  // 白名单的镜像仓库列表
}

func (s *WebhookServer) Handler(writer http.ResponseWriter, request *http.Request)  {
	var body []byte
	if request.Body != nil {
		if data, err := ioutil.ReadAll(request.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		klog.Error("empty data body")
		http.Error(writer, "empty data body", http.StatusBadRequest)
		return
	}

	// 校验 content-type
	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("Content-Type is %s, but expect application/json", contentType)
		http.Error(writer, "Content-Type invalid, expect application/json", http.StatusBadRequest)
		return
	}

	// 数据序列化（validate、mutate）请求的数据都是 AdmissionReview
	var admissionResponse *admissionV1.AdmissionResponse
	requestedAdmissionReview := admissionV1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &requestedAdmissionReview); err != nil {
		klog.Errorf("Can't decode body: %v", err)
		admissionResponse = &admissionV1.AdmissionResponse{
			Result: &metav1.Status{
				Code: http.StatusInternalServerError,
				Message: err.Error(),
			},
		}
	} else {
		// 序列化成功，也就是说获取到了请求的 AdmissionReview 的数据
		if request.URL.Path == "/mutate" {
			// TODO
		} else if request.URL.Path == "/validate" {
			admissionResponse = s.validate(&requestedAdmissionReview)
		}
	}

	// 构造返回的 AdmissionReview 这个结构体
	responseAdmissionReview := admissionV1.AdmissionReview{}
	// admission/v1
	responseAdmissionReview.APIVersion = requestedAdmissionReview.APIVersion
	responseAdmissionReview.Kind = requestedAdmissionReview.Kind
	if admissionResponse != nil {
		responseAdmissionReview.Response = admissionResponse
		if requestedAdmissionReview.Request != nil { // 返回相同的 UID
			responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		}

	}

	klog.Info(fmt.Sprintf("sending response: %v", responseAdmissionReview.Response))
	// send response
	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		klog.Errorf("Can't encode response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't encode response: %v", err), http.StatusBadRequest)
		return
	}
	klog.Info("Ready to write response...")

	if _, err := writer.Write(respBytes); err != nil {
		klog.Errorf("Can't write response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't write reponse: %v", err), http.StatusBadRequest)
	}
}

func (s *WebhookServer) validate(ar *admissionV1.AdmissionReview) *admissionV1.AdmissionResponse {
	req := ar.Request
	var (
		allowed = true
		code = http.StatusOK
		message = ""
	)

	klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%s UID=%s",
		req.Kind.Kind, req.Namespace, req.Name, req.UID)

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Errorf("Can't unmarshal object raw: %v", err)
		allowed = false
		code = http.StatusBadRequest
		return &admissionV1.AdmissionResponse{
			Allowed: allowed,
			Result: &metav1.Status{
				Code: int32(code),
				Message: err.Error(),
			},
		}
	}

	// 处理真正的业务逻辑
	for _, container := range pod.Spec.Containers {
		var whitelisted = false
		for _, reg := range s.WhiteListRegistries {
			if strings.HasPrefix(container.Image, reg) {
				whitelisted = true
			}
		}
		if !whitelisted {
			allowed = false
			code = http.StatusForbidden
			message = fmt.Sprintf("%s image comes from an untrusted registry! Only images from %v are allowed.", container.Image, s.WhiteListRegistries)
			break
		}
	}

	return &admissionV1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Code: int32(code),
			Message: message,
		},
	}
}