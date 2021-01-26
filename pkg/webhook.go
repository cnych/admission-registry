package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog"
)

var (
	runtimeScheme = runtime.NewScheme()
	codeFactory   = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codeFactory.UniversalDeserializer()
)

const (
	AnnotationMutateKey = "io.ydzs.admission-registry/mutate" // io.ydzs.admission-registry/mutate=no/off/false/n
	AnnotationStatusKey = "io.ydzs.admission-registry/status" // io.ydzs.admission-registry/status=mutated
)

type WhSvrParam struct {
	Port     int
	CertFile string
	KeyFile  string
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type WebhookServer struct {
	Server              *http.Server // http server
	WhiteListRegistries []string     // 白名单的镜像仓库列表
}

func (s *WebhookServer) Handler(writer http.ResponseWriter, request *http.Request) {
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
	var admissionResponse *admissionv1.AdmissionResponse
	requestedAdmissionReview := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &requestedAdmissionReview); err != nil {
		klog.Errorf("Can't decode body: %v", err)
		admissionResponse = &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			},
		}
	} else {
		// 序列化成功，也就是说获取到了请求的 AdmissionReview 的数据
		if request.URL.Path == "/mutate" {
			admissionResponse = s.mutate(&requestedAdmissionReview)
		} else if request.URL.Path == "/validate" {
			admissionResponse = s.validate(&requestedAdmissionReview)
		}
	}

	// 构造返回的 AdmissionReview 这个结构体
	responseAdmissionReview := admissionv1.AdmissionReview{}
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

func (s *WebhookServer) validate(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	req := ar.Request
	var (
		allowed = true
		code    = http.StatusOK
		message = ""
	)

	klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%s UID=%s",
		req.Kind.Kind, req.Namespace, req.Name, req.UID)

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Errorf("Can't unmarshal object raw: %v", err)
		allowed = false
		code = http.StatusBadRequest
		return &admissionv1.AdmissionResponse{
			Allowed: allowed,
			Result: &metav1.Status{
				Code:    int32(code),
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

	return &admissionv1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Code:    int32(code),
			Message: message,
		},
	}
}

func (s *WebhookServer) mutate(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	// Deployment、Service -> annotations： AnnotationMutateKey， AnnotationStatusKey
	req := ar.Request

	var (
		objectMeta *metav1.ObjectMeta
	)

	klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%s UID=%s",
		req.Kind.Kind, req.Namespace, req.Name, req.UID)

	switch req.Kind.Kind {
	case "Deployment":
		var deployment appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &deployment); err != nil {
			klog.Errorf("Can't not unmarshal raw object: %v", err)
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Code:    http.StatusBadRequest,
					Message: err.Error(),
				},
			}

		}
		objectMeta = &deployment.ObjectMeta
	case "Service":
		var service corev1.Service
		if err := json.Unmarshal(req.Object.Raw, &service); err != nil {
			klog.Errorf("Can't not unmarshal raw object: %v", err)
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Code:    http.StatusBadRequest,
					Message: err.Error(),
				},
			}
		}
		objectMeta = &service.ObjectMeta
	default:
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("Can't handle the kind(%s) object", req.Kind.Kind),
			},
		}
	}

	// 判断是否需要真的执行 mutate 操作
	if !mutationRequired(objectMeta) {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	// 需要执行 mutate 操作

	annotations := map[string]string{
		AnnotationStatusKey: "mutated",
	}

	var patch []patchOperation
	patch = append(patch, mutateAnnotations(objectMeta.GetAnnotations(), annotations)...)

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		klog.Errorf("patch marshal error: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		}
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func mutationRequired(metadata *metav1.ObjectMeta) bool {
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	var required bool

	switch strings.ToLower(annotations[AnnotationMutateKey]) {
	case "n", "no", "false", "off":
		required = false
	default:
		required = true
	}

	status := annotations[AnnotationStatusKey]
	if strings.ToLower(status) == "mutated" {
		required = false
	}

	klog.Infof("Mutation policy for %s/%s: required: %v", metadata.Name, metadata.Namespace, required)

	return required
}

func mutateAnnotations(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return
}
