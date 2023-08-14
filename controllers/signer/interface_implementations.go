package signer

import (
	"crypto/x509"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type certificateRequestImpl struct {
	*cmapi.CertificateRequest
}

var _ RequestObject = &certificateRequestImpl{}

func RequestObjectFromCertificateRequest(cr *cmapi.CertificateRequest) RequestObject {
	return &certificateRequestImpl{cr}
}

func (c *certificateRequestImpl) GetRequest() (*x509.Certificate, time.Duration, []byte, error) {
	duration := apiutil.DefaultCertDuration(c.CertificateRequest.Spec.Duration)

	template, err := pki.GenerateTemplateFromCertificateRequest(c.CertificateRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	return template, duration, c.Spec.Request, nil
}

func (c *certificateRequestImpl) GetConditions() []RequestCondition {
	conditions := make([]RequestCondition, 0, len(c.Status.Conditions))
	for _, condition := range c.Status.Conditions {
		var lastTransition metav1.Time
		if condition.LastTransitionTime != nil {
			lastTransition = *condition.LastTransitionTime
		}

		conditions = append(conditions, RequestCondition{
			Type:               string(condition.Type),
			Status:             metav1.ConditionStatus(condition.Status),
			Reason:             condition.Reason,
			Message:            condition.Message,
			LastUpdateTime:     metav1.Time{},
			LastTransitionTime: lastTransition,
		})
	}
	return conditions
}

type certificateSigningRequestImpl struct {
	*certificatesv1.CertificateSigningRequest
}

var _ RequestObject = &certificateSigningRequestImpl{}

func RequestObjectFromCertificateSigningRequest(csr *certificatesv1.CertificateSigningRequest) RequestObject {
	return &certificateSigningRequestImpl{csr}
}

func (c *certificateSigningRequestImpl) GetRequest() (*x509.Certificate, time.Duration, []byte, error) {
	duration, err := pki.DurationFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	template, err := pki.GenerateTemplateFromCertificateSigningRequest(c.CertificateSigningRequest)
	if err != nil {
		return nil, 0, nil, err
	}

	return template, duration, c.Spec.Request, nil
}

func (c *certificateSigningRequestImpl) GetConditions() []RequestCondition {
	conditions := make([]RequestCondition, 0, len(c.Status.Conditions))
	for _, condition := range c.Status.Conditions {
		conditions = append(conditions, RequestCondition{
			Type:               string(condition.Type),
			Status:             metav1.ConditionStatus(condition.Status),
			Reason:             condition.Reason,
			Message:            condition.Message,
			LastUpdateTime:     condition.LastUpdateTime,
			LastTransitionTime: condition.LastTransitionTime,
		})
	}
	return conditions
}
