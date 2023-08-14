/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The SetRequestConditionError error is meant to be returned by the
// Sign function. When Sign returns this error, the caller (i.e., the certificate
// request controller) is expected to update the CertificateRequest with the
// condition contained in the error.
//
// The error wrapped by this error is the error can still be a signer.Permanent or
// signer.Pending error and will be handled accordingly.
//
// > This error should be returned only by the Sign function.
type SetRequestConditionError struct {
	Err error

	ConditionType   string
	ConditionStatus metav1.ConditionStatus
	ConditionReason string
}

var _ error = SetRequestConditionError{}

func (ve SetRequestConditionError) Unwrap() error {
	return ve.Err
}

func (ve SetRequestConditionError) Error() string {
	return ve.Err.Error()
}
